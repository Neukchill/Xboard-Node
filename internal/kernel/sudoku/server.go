package sudoku

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sudokuapis "github.com/SUDOKU-ASCII/sudoku/apis"
	"github.com/SUDOKU-ASCII/sudoku/pkg/obfs/httpmask"
	sudokutable "github.com/SUDOKU-ASCII/sudoku/pkg/obfs/sudoku"
)

// readHandshakeBytes reads the initial client-hello burst from conn.
//
// The caller must have already set a read deadline on rawConn (the underlying
// TCP/TLS connection).  readHandshakeBytes blocks until the first chunk of
// data arrives, then uses a 20 ms short-deadline loop to drain any additional
// bytes that arrived in the same burst.  Because the sudoku client sends the
// entire client hello before waiting for the server hello, all handshake bytes
// arrive in a single burst and this function captures them completely.
func readHandshakeBytes(conn net.Conn, rawConn net.Conn) ([]byte, error) {
	tmp := make([]byte, 4096)

	// First read: waits up to the caller-set deadline for data.
	n, err := conn.Read(tmp)
	if n == 0 {
		return nil, err
	}
	buf := make([]byte, n, n+4096)
	copy(buf, tmp[:n])
	if err != nil {
		// EOF / deadline on first read with data is fine.
		return buf, nil
	}

	// Short-deadline reads to capture any additional buffered bytes.
	for len(buf) < 32*1024 {
		rawConn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		n, err = conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break // deadline exceeded or connection gone — we have enough
		}
	}
	return buf, nil
}

// NodeSettings holds node-level (shared across all users) configuration.
type NodeSettings struct {
	// Table/obfuscation settings
	TableType          string // e.g. "up_ascii_down_entropy"
	CustomTable        string // e.g. "vpvpvvxx" (optional)
	CustomTables       []string
	AEADMethod         string // "chacha20-poly1305" or "aes-128-gcm"
	PaddingMin         int
	PaddingMax         int
	EnablePureDownlink bool

	// HTTP mask settings
	HTTPMaskMode     string // "legacy","ws","stream","poll","auto"
	HTTPMaskPathRoot string // optional path prefix
	HTTPMaskMux      string // "off","auto","on"

	// Per-user key derivation
	KeySalt string // random salt stored in node config

	// Server settings
	HandshakeTimeout int // seconds (default 10)
	Listen           string
	TLSConfig        *tls.Config
}

// userEntry represents a registered user with their derived key and protocol config.
type userEntry struct {
	id       int
	uuid     string
	salt     string
	key      string // derived: hex(sha256(uuid+salt))
	settings NodeSettings
	extras   map[string]any
	cfg      *sudokuapis.ProtocolConfig
}

// deriveKey computes the per-user PSK from UUID and node salt.
func deriveKey(uuid, salt string) string {
	h := sha256.Sum256([]byte(uuid + salt))
	return fmt.Sprintf("%x", h[:])
}

func mergeNodeSettings(base, override NodeSettings) NodeSettings {
	merged := base
	if override.TableType != "" {
		merged.TableType = override.TableType
	}
	if override.CustomTable != "" {
		merged.CustomTable = override.CustomTable
	}
	if len(override.CustomTables) > 0 {
		merged.CustomTables = append([]string(nil), override.CustomTables...)
		merged.CustomTable = ""
	}
	if override.AEADMethod != "" {
		merged.AEADMethod = override.AEADMethod
	}
	if override.PaddingMin != 0 {
		merged.PaddingMin = override.PaddingMin
	}
	if override.PaddingMax != 0 {
		merged.PaddingMax = override.PaddingMax
	}
	if override.EnablePureDownlink {
		merged.EnablePureDownlink = true
	}
	if override.HTTPMaskMode != "" {
		merged.HTTPMaskMode = override.HTTPMaskMode
	}
	if override.HTTPMaskPathRoot != "" {
		merged.HTTPMaskPathRoot = override.HTTPMaskPathRoot
	}
	if override.HTTPMaskMux != "" {
		merged.HTTPMaskMux = override.HTTPMaskMux
	}
	if override.KeySalt != "" {
		merged.KeySalt = override.KeySalt
	}
	return merged
}

func finalizeUserEntry(base NodeSettings, entry userEntry) userEntry {
	entry.settings = mergeNodeSettings(base, entry.settings)
	if entry.key == "" {
		entry.key = deriveKey(entry.uuid, entry.salt)
	}
	entry.cfg = buildConfig(entry.key, entry.settings)
	return entry
}

func userHandshakeHash(key string) string {
	h := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", h[:8])
}

func findMatchedUserNoLog(handshakeBytes []byte, users []userEntry, disableInnerHTTPMask bool) int {
	for i, user := range users {
		probeCfg := user.cfg
	if disableInnerHTTPMask {
			inner := *user.cfg
		inner.DisableHTTPMask = true
		probeCfg = &inner
	}
		if sudokuapis.ProbeHandshake(handshakeBytes, probeCfg) == nil {
			return i
		}
	}
	return -1
}

// buildConfig creates the ProtocolConfig for a single user given their key and node settings.
func buildConfig(key string, s NodeSettings) *sudokuapis.ProtocolConfig {
	var (
		table  *sudokutable.Table
		tables []*sudokutable.Table
	)
	if len(s.CustomTables) > 0 {
		tableSet, err := sudokutable.NewTableSet(key, s.TableType, s.CustomTables)
		if err == nil && tableSet != nil && len(tableSet.Tables) > 0 {
			tables = tableSet.Tables
			table = tables[0]
		}
	}
	if table == nil {
		if s.CustomTable != "" {
			t, err := sudokutable.NewTableWithCustom(key, s.TableType, s.CustomTable)
			if err != nil {
				// Fall back to standard table on invalid custom pattern
				t = sudokutable.NewTable(key, s.TableType)
			}
			table = t
		} else {
			table = sudokutable.NewTable(key, s.TableType)
		}
	}

	timeout := s.HandshakeTimeout
	if timeout <= 0 {
		timeout = 10
	}

	method := s.AEADMethod
	if method == "" {
		method = "chacha20-poly1305"
	}

	return &sudokuapis.ProtocolConfig{
		Key:                     key,
		AEADMethod:              method,
		Table:                   table,
		Tables:                  tables,
		PaddingMin:              s.PaddingMin,
		PaddingMax:              s.PaddingMax,
		EnablePureDownlink:      s.EnablePureDownlink,
		HandshakeTimeoutSeconds: timeout,
		HTTPMaskMode:            s.HTTPMaskMode,
		HTTPMaskPathRoot:        s.HTTPMaskPathRoot,
		HTTPMaskMultiplex:       s.HTTPMaskMux,
		// HTTPMaskTLSEnabled is client-only; server uses the TLS listener.
	}
}

// trafficCounter holds per-user atomic byte counters.
type trafficCounter struct {
	upload   atomic.Int64
	download atomic.Int64
}

// connRecord tracks a live proxied connection.
type connRecord struct {
	userID int
	uuid   string
	client net.Conn
}

type wsMessageReader interface {
	HTTPMaskReadMessage(maxBytes int, timeout time.Duration) ([]byte, error)
}

// Server is the running Sudoku multi-user proxy server.
type Server struct {
	settings NodeSettings
	log      *slog.Logger
	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc

	// httpmaskServer handles WebSocket / HTTP-tunnel upgrade for non-legacy modes
	// (ws / stream / poll / auto). nil for legacy or no-mask mode.
	// After the upgrade, the inner Sudoku handshake runs with DisableHTTPMask=true.
	httpmaskServer *httpmask.TunnelServer

	usersMu sync.RWMutex
	users   []userEntry // ordered list; sequential probe tries in this order

	trafficMu sync.Mutex
	traffic   map[int]*trafficCounter

	connsMu    sync.RWMutex
	conns      map[string]*connRecord
	activeConn atomic.Int64
	totalConn  atomic.Int64
}

// NewServer creates a Server (not yet started).
func NewServer(settings NodeSettings, log *slog.Logger) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		settings: settings,
		log:      log,
		ctx:      ctx,
		cancel:   cancel,
		traffic:  make(map[int]*trafficCounter),
		conns:    make(map[string]*connRecord),
	}
}

// Start binds the listener and begins accepting connections.
func (s *Server) Start() error {
	switch strings.ToLower(strings.TrimSpace(s.settings.HTTPMaskMode)) {
	case "ws", "stream", "poll", "auto":
		s.httpmaskServer = httpmask.NewTunnelServer(httpmask.TunnelServerOptions{
			Mode:                s.settings.HTTPMaskMode,
			PathRoot:            s.settings.HTTPMaskPathRoot,
			PassThroughOnReject: true,
		})
	}

	var ln net.Listener
	var err error
	if s.settings.TLSConfig != nil {
		ln, err = tls.Listen("tcp", s.settings.Listen, s.settings.TLSConfig)
	} else {
		ln, err = net.Listen("tcp", s.settings.Listen)
	}
	if err != nil {
		return fmt.Errorf("sudoku: listen %s: %w", s.settings.Listen, err)
	}
	s.listener = ln
	s.log.Info("sudoku server listening",
		"addr", s.settings.Listen,
		"tls", s.settings.TLSConfig != nil,
		"httpmask_mode", s.settings.HTTPMaskMode,
		"httpmask_tunnel", s.httpmaskServer != nil,
	)
	go s.acceptLoop()
	return nil
}

// Stop shuts down the server and all active connections.
func (s *Server) Stop() {
	s.cancel()
	if s.listener != nil {
		_ = s.listener.Close()
	}
	s.connsMu.Lock()
	for _, r := range s.conns {
		_ = r.client.Close()
	}
	s.connsMu.Unlock()
}

// UpdateUsers atomically replaces the full user list.
// Returns (added, removed) counts.
func (s *Server) UpdateUsers(entries []userEntry) (added, removed int) {
	filled := make([]userEntry, 0, len(entries))
	for _, e := range entries {
		e = finalizeUserEntry(s.settings, e)
		filled = append(filled, e)
	}

	s.usersMu.Lock()
	old := s.users
	s.users = filled
	s.usersMu.Unlock()

	oldSet := make(map[int]struct{}, len(old))
	for _, u := range old {
		oldSet[u.id] = struct{}{}
	}
	newSet := make(map[int]struct{}, len(filled))
	for _, u := range filled {
		newSet[u.id] = struct{}{}
	}
	for id := range newSet {
		if _, exists := oldSet[id]; !exists {
			added++
		}
	}
	for id := range oldSet {
		if _, exists := newSet[id]; !exists {
			removed++
		}
	}
	return
}

// AddUsers appends users not already registered. Returns added count.
func (s *Server) AddUsers(entries []userEntry) int {
	s.usersMu.Lock()
	defer s.usersMu.Unlock()

	existing := make(map[int]struct{}, len(s.users))
	for _, u := range s.users {
		existing[u.id] = struct{}{}
	}
	added := 0
	for _, e := range entries {
		if _, ok := existing[e.id]; ok {
			continue
		}
		e = finalizeUserEntry(s.settings, e)
		s.users = append(s.users, e)
		existing[e.id] = struct{}{}
		added++
	}
	return added
}

// RemoveUsers removes users by ID. Returns removed count.
func (s *Server) RemoveUsers(ids []int) int {
	removeSet := make(map[int]struct{}, len(ids))
	for _, id := range ids {
		removeSet[id] = struct{}{}
	}

	s.usersMu.Lock()
	var kickUUIDs []string
	newUsers := s.users[:0]
	for _, u := range s.users {
		if _, remove := removeSet[u.id]; remove {
			kickUUIDs = append(kickUUIDs, u.uuid)
		} else {
			newUsers = append(newUsers, u)
		}
	}
	removed := len(s.users) - len(newUsers)
	s.users = newUsers
	s.usersMu.Unlock()

	for _, uuid := range kickUUIDs {
		s.CloseUserConns(uuid)
	}
	return removed
}

// CloseUserConns forcibly closes all connections for the given UUID.
func (s *Server) CloseUserConns(uuid string) {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	for id, r := range s.conns {
		if r.uuid == uuid {
			_ = r.client.Close()
			delete(s.conns, id)
			s.activeConn.Add(-1)
		}
	}
}

// GetTraffic returns and resets per-user traffic counters.
func (s *Server) GetTraffic() map[int][2]int64 {
	s.trafficMu.Lock()
	old := s.traffic
	s.traffic = make(map[int]*trafficCounter, len(old))
	s.trafficMu.Unlock()

	out := make(map[int][2]int64, len(old))
	for id, c := range old {
		up := c.upload.Load()
		dn := c.download.Load()
		if up > 0 || dn > 0 {
			out[id] = [2]int64{up, dn}
		}
	}
	return out
}

// GetAliveIPs returns per-user sets of currently connected source IPs.
func (s *Server) GetAliveIPs() map[int]map[string]bool {
	s.connsMu.RLock()
	defer s.connsMu.RUnlock()
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()

	uuidToID := make(map[string]int, len(s.users))
	for _, u := range s.users {
		uuidToID[u.uuid] = u.id
	}

	out := make(map[int]map[string]bool)
	for _, r := range s.conns {
		id, ok := uuidToID[r.uuid]
		if !ok {
			continue
		}
		if out[id] == nil {
			out[id] = make(map[string]bool)
		}
		host, _, err := net.SplitHostPort(r.client.RemoteAddr().String())
		if err == nil {
			out[id][host] = true
		}
	}
	return out
}

// ActiveConnCount returns the number of live connections.
func (s *Server) ActiveConnCount() int { return int(s.activeConn.Load()) }

// ─── internal ─────────────────────────────────────────────────────────────────

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				s.log.Error("accept error", "err", err)
				time.Sleep(10 * time.Millisecond)
				continue
			}
		}
		go s.handleConn(conn)
	}
}

// handleConn authenticates an incoming connection using a two-phase approach:
//
// Phase 1 — buffer: read all client-hello bytes into memory in one burst.
//
// Phase 2 — identify: for each registered user, run ServerHandshakeCore
// against a sinkConn (reads from bytes.Reader, writes to /dev/null).
// This is completely stateless — every probe sees an independent copy of the
// bytes, there are no goroutine leaks between probes, and no lock contention.
//
// Phase 3 — handshake: replay the buffered bytes via NewPreBufferedConn and
// run the full ServerHandshakeSessionAutoWithUserHash on the real connection
// for the matched user only.
func (s *Server) handleConn(rawConn net.Conn) {
	defer rawConn.Close()

	// Snapshot the current user list.
	s.usersMu.RLock()
	users := make([]userEntry, len(s.users))
	copy(users, s.users)
	s.usersMu.RUnlock()

	if len(users) == 0 {
		s.log.Debug("no users registered, dropping connection", "remote", rawConn.RemoteAddr())
		return
	}

	// Outer HTTPMask upgrade (ws / stream / poll / auto modes).
	var current net.Conn = rawConn
	disableInnerHTTPMask := false
	wsTunnelMode := false

	if s.httpmaskServer != nil {
		res, c, err := s.httpmaskServer.HandleConn(rawConn)
		if err != nil {
			s.log.Debug("httpmask tunnel error", "remote", rawConn.RemoteAddr(), "err", err)
			return
		}
		switch res {
		case httpmask.HandleDone:
			return
		case httpmask.HandleStartTunnel:
			current = c
			disableInnerHTTPMask = true
			_, wsTunnelMode = c.(wsMessageReader)
		case httpmask.HandlePassThrough:
			current = c
		default:
			return
		}
	}

	// ── Phase 1: buffer ──────────────────────────────────────────────────────
	timeout := s.settings.HandshakeTimeout
	if timeout <= 0 {
		timeout = 10
	}

	var handshakeBytes []byte
	matchedIndex := -1

	if earlyHash, ok := httpmask.EarlyHandshakeUserHash(current); ok {
		for i, user := range users {
			if userHandshakeHash(user.key) == earlyHash {
				matchedIndex = i
				// fmt.Printf("[sudoku-debug] EARLY META MATCH user_id=%d hash=%s\n", user.id, earlyHash)
				break
			}
		}
	}

	if matchedIndex < 0 && disableInnerHTTPMask {
		if wsTunnelMode {
			// WS tunnel mode: some clients split the hello across multiple WS
			// messages. Keep appending messages until probe can identify the user.
			reader, ok := current.(wsMessageReader)
			if !ok {
				// fmt.Printf("[sudoku-debug] PHASE1 FAIL (ws/no-message-reader) remote=%s\n",
				// 	rawConn.RemoteAddr())
				return
			}
			deadline := time.Now().Add(time.Duration(timeout) * time.Second)
			for len(handshakeBytes) < 32*1024 {
				remaining := time.Until(deadline)
				if remaining <= 0 {
					break
				}
				chunk, readErr := reader.HTTPMaskReadMessage(32*1024-len(handshakeBytes), remaining)
				if readErr != nil {
					if len(handshakeBytes) == 0 {
						// fmt.Printf("[sudoku-debug] PHASE1 READ ERR (ws) remote=%s err=%v\n",
						// 	rawConn.RemoteAddr(), readErr)
					}
					break
				}
				if len(chunk) == 0 {
					break
				}
				handshakeBytes = append(handshakeBytes, chunk...)
				// fmt.Printf("[sudoku-debug] PHASE1 WS APPEND remote=%s chunk=%d total=%d\n",
				// 	rawConn.RemoteAddr(), len(chunk), len(handshakeBytes))
				matchedIndex = findMatchedUserNoLog(handshakeBytes, users, true)
				if matchedIndex >= 0 {
					break
				}
			}
			if len(handshakeBytes) == 0 {
				// fmt.Printf("[sudoku-debug] PHASE1 FAIL (ws/empty) remote=%s\n",
				// 	rawConn.RemoteAddr())
				return
			}
		} else {
			// stream / poll tunnel mode still behaves like a regular byte stream.
			// Keep the original burst-drain logic here; using single-read would
			// reintroduce partial-handshake bugs for non-WS tunnels.
			rawConn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
			var readErr error
			handshakeBytes, readErr = readHandshakeBytes(current, rawConn)
			rawConn.SetReadDeadline(time.Time{})
			if readErr != nil && len(handshakeBytes) == 0 {
				s.log.Debug("no handshake data received", "remote", rawConn.RemoteAddr(), "err", readErr)
				return
			}
		}
	} else {
		// Plain TCP / TLS mode: burst-drain 对 raw TCP 是安全的。
		rawConn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
		var readErr error
		handshakeBytes, readErr = readHandshakeBytes(current, rawConn)
		rawConn.SetReadDeadline(time.Time{})
		if readErr != nil && len(handshakeBytes) == 0 {
			s.log.Debug("no handshake data received", "remote", rawConn.RemoteAddr(), "err", readErr)
			return
		}
	}

	if matchedIndex < 0 && len(handshakeBytes) == 0 {
		s.log.Debug("empty handshake, dropping", "remote", rawConn.RemoteAddr())
		return
	}

	// ── Phase 2: identify ────────────────────────────────────────────────────
	// Try each user's config against an in-memory sinkConn.
	// ServerHandshakeCore does: HTTP-mask peek → table probe → AEAD decrypt
	// client-hello → write server-hello (discarded) → return.
	// It does NOT read the session/OpenTCP message, so it completes entirely
	// within the already-buffered bytes.
	// Phase 2 uses sudokuapis.ProbeHandshake — a pure in-memory function that
	// calls the library's internal probeHandshakeBytes directly.  It uses
	// bytes.NewReader, starts no goroutines, and has no side effects on any
	// connection.  This eliminates all goroutine-leak / lock-contention issues.
	if matchedIndex < 0 {
		for i, user := range users {
			probeCfg := user.cfg
			if disableInnerHTTPMask {
				inner := *user.cfg
				inner.DisableHTTPMask = true
				probeCfg = &inner
			}
			probeErr := sudokuapis.ProbeHandshake(handshakeBytes, probeCfg)

			// fmt.Printf("[sudoku-debug] PROBE %s index=%d user_id=%d buf=%d err=%v\n",
			// 	map[bool]string{true: "SUCCESS", false: "FAIL"}[probeErr == nil],
			// 	i, user.id, len(handshakeBytes), probeErr)

			if probeErr == nil {
				if extraKeys := debugExtraKeys(user.extras); extraKeys != "" {
					// fmt.Printf("[sudoku-debug] USER EXTRAS MATCH index=%d user_id=%d keys=%s\n",
					// 	i, user.id, extraKeys)
				}
				matchedIndex = i
				break
			}
		}
	} else {
		if extraKeys := debugExtraKeys(users[matchedIndex].extras); extraKeys != "" {
			// fmt.Printf("[sudoku-debug] USER EXTRAS MATCH index=%d user_id=%d keys=%s\n",
			// 	matchedIndex, users[matchedIndex].id, extraKeys)
		}
		// fmt.Printf("[sudoku-debug] PROBE SUCCESS index=%d user_id=%d buf=%d err=<nil>\n",
		// 	matchedIndex, users[matchedIndex].id, len(handshakeBytes))
	}

	if matchedIndex < 0 {
		s.log.Debug("all user configs exhausted, dropping connection", "remote", rawConn.RemoteAddr())
		return
	}

	// ── Phase 3: real handshake ───────────────────────────────────────────────
	// Replay the buffered bytes on top of the real connection and run the full
	// handshake + session-message read for the matched user.
	//
	// IMPORTANT: Always use PreBufferedConn even when EarlyHandshakeUserHash
	// matched. The early-handshake shortcut inside serverHandshakeCoreWithUserHash
	// skips the entire handshake (read client hello, write server hello, rekey).
	// Without PreBufferedConn, Phase 3 has no bytes to replay, causing the
	// client to wait forever for server hello while the server waits for the
	// session message — a deadlock.  By always using PreBufferedConn, we bypass
	// the shortcut and let the handshake library read from the buffered bytes,
	// completing the full KIP exchange correctly.
	matchedUser := users[matchedIndex]
	realCfg := matchedUser.cfg
	if disableInnerHTTPMask {
		inner := *matchedUser.cfg
		inner.DisableHTTPMask = true
		realCfg = &inner
	}

	// Debug: output user config details
	extrasKeys := debugExtraKeys(matchedUser.extras)
	// fmt.Printf("[sudoku-debug] USER CONFIG user_id=%d uuid=%s key=%s salt=%s extras=[%s] tableType=%s aead=%s padding=[%d,%d] httpmask=%s\n",
	// 	matchedUser.id,
	// 	matchedUser.uuid,
	// 	matchedUser.key[:min(16, len(matchedUser.key))],
	// 	matchedUser.salt[:min(8, len(matchedUser.salt))],
	// 	extrasKeys,
	// 	matchedUser.settings.TableType,
	// 	matchedUser.settings.AEADMethod,
	// 	matchedUser.settings.PaddingMin,
	// 	matchedUser.settings.PaddingMax,
	// 	matchedUser.settings.HTTPMaskMode,
	// )
	_ = extrasKeys // avoid unused variable warning

	defer func() {
		if r := recover(); r != nil {
			// fmt.Printf("[sudoku-debug] PHASE3 PANIC user_id=%d r=%v\n", matchedUser.id, r)
			_ = r
		}
	}()

	// fmt.Printf("[sudoku-debug] PHASE3 BEGIN user_id=%d buf=%d remote=%s\n",
	// 	matchedUser.id, len(handshakeBytes), rawConn.RemoteAddr())

	// Phase 1 (HTTPMaskReadMessage) consumed the client hello from the WebSocket
	// stream and cached it in handshakeBytes.  PreBufferedConn replays those bytes
	// so the handshake library can parse the client hello again, write server
	// hello back, and rekey — completing the full KIP handshake.
	phase3Conn := sudokuapis.NewPreBufferedConn(current, handshakeBytes)
	conn, session, targetAddr, _, _, err := sudokuapis.ServerHandshakeSessionAutoWithUserHash(phase3Conn, realCfg)
	if err != nil {
	    // fmt.Printf("[sudoku-debug] PHASE3 HANDSHAKE FAIL user_id=%d err=%v\n",
	    //     matchedUser.id, err)
	    return
	}

	// fmt.Printf("[sudoku-debug] PHASE3 HANDSHAKE OK user_id=%d session=%v target=%s\n",
	// 	matchedUser.id, session, targetAddr)

	s.proxy(conn, session, targetAddr, matchedUser)

	// fmt.Printf("[sudoku-debug] PHASE3 PROXY EXITED user_id=%d target=%s\n",
	// 	matchedUser.id, targetAddr)
}

// proxy relays traffic between the authenticated tunnel connection and the target.
func (s *Server) proxy(conn net.Conn, session sudokuapis.SessionKind, targetAddr string, user userEntry) {
	connID := conn.RemoteAddr().String()

	s.connsMu.Lock()
	s.conns[connID] = &connRecord{userID: user.id, uuid: user.uuid, client: conn}
	s.connsMu.Unlock()
	s.activeConn.Add(1)
	s.totalConn.Add(1)

	defer func() {
		s.connsMu.Lock()
		delete(s.conns, connID)
		s.connsMu.Unlock()
		s.activeConn.Add(-1)
		_ = conn.Close()
	}()

	switch session {
	case sudokuapis.SessionUoT:
		if err := sudokuapis.HandleUoT(conn); err != nil {
			s.log.Debug("UoT session ended", "uuid", user.uuid, "err", err)
		}

	case sudokuapis.SessionMux:
		err := sudokuapis.HandleMuxWithDialer(conn,
			func(addr string) { s.log.Debug("mux sub-stream", "uuid", user.uuid, "target", addr) },
			func(addr string) (net.Conn, error) {
				target, err := net.DialTimeout("tcp", addr, 10*time.Second)
				if err != nil {
					return nil, err
				}
				return &countingConn{Conn: target, userID: user.id, srv: s}, nil
			},
		)
		if err != nil {
			s.log.Debug("mux session ended", "uuid", user.uuid, "err", err)
		}

	default: // SessionForward
		target, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
		if err != nil {
	        // fmt.Printf("[sudoku-debug] DIAL TARGET FAIL target=%s user_id=%d err=%v\n",
	        //     targetAddr, user.id, err)
	        s.log.Error("dial target failed", "target", targetAddr, "uuid", user.uuid, "err", err)
	        return
		}
		// fmt.Printf("[sudoku-debug] DIAL TARGET OK target=%s user_id=%d\n", targetAddr, user.id)
		defer target.Close()

		up, dn := relay(conn, target)
		s.addTraffic(user.id, up, dn)
		s.log.Debug("connection closed",
			"uuid", user.uuid,
			"target", targetAddr,
			"upload", up,
			"download", dn,
		)
	}
}

func (s *Server) addTraffic(userID int, upload, download int64) {
	if upload == 0 && download == 0 {
		return
	}
	s.trafficMu.Lock()
	c, ok := s.traffic[userID]
	if !ok {
		c = &trafficCounter{}
		s.traffic[userID] = c
	}
	s.trafficMu.Unlock()
	c.upload.Add(upload)
	c.download.Add(download)
}

// relay copies data in both directions and returns (upload, download) byte counts.
func relay(client, target net.Conn) (upload, download int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		upload, _ = io.Copy(target, client)
		if tc, ok := target.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		download, _ = io.Copy(client, target)
		if tc, ok := client.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
	return
}

// countingConn wraps a net.Conn and attributes bytes to a user.
type countingConn struct {
	net.Conn
	userID int
	srv    *Server
}

func (c *countingConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		c.srv.addTraffic(c.userID, 0, int64(n))
	}
	return
}

func (c *countingConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		c.srv.addTraffic(c.userID, int64(n), 0)
	}
	return
}
