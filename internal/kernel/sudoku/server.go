package sudoku

import (
	"bytes"
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

// sinkConn is used exclusively for per-user probe attempts in handleConn.
//
// Reads come from an in-memory bytes.Reader so they are always instantaneous
// and never block or interact with the real network connection.  Writes are
// silently discarded so the library's "write server hello" step does not
// fail during probing.  Deadline methods are no-ops so a probe cannot
// disturb the real connection's read deadline.
//
// Because every byte is served from an already-complete in-memory snapshot,
// any goroutine spawned internally by crypto.NewRecordConn will immediately
// receive io.EOF when it tries to read beyond the available bytes and will
// exit on its own — eliminating the goroutine-leak / lock-contention problem
// that broke the previous replayableConn approach.
type sinkConn struct {
	reader  *bytes.Reader
	realFor net.Conn // used only for LocalAddr / RemoteAddr
}

func newSinkConn(data []byte, realFor net.Conn) *sinkConn {
	return &sinkConn{reader: bytes.NewReader(data), realFor: realFor}
}

func (c *sinkConn) Read(p []byte) (int, error)         { return c.reader.Read(p) }
func (c *sinkConn) Write(p []byte) (int, error)        { return len(p), nil } // discard
func (c *sinkConn) Close() error                       { return nil }
func (c *sinkConn) LocalAddr() net.Addr                { return c.realFor.LocalAddr() }
func (c *sinkConn) RemoteAddr() net.Addr               { return c.realFor.RemoteAddr() }
func (c *sinkConn) SetDeadline(time.Time) error        { return nil }
func (c *sinkConn) SetReadDeadline(time.Time) error    { return nil }
func (c *sinkConn) SetWriteDeadline(time.Time) error   { return nil }

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
	id   int
	uuid string
	salt string
	key  string              // derived: hex(sha256(uuid+salt))
	cfg  *sudokuapis.ProtocolConfig
}

// deriveKey computes the per-user PSK from UUID and node salt.
func deriveKey(uuid, salt string) string {
	h := sha256.Sum256([]byte(uuid + salt))
	return fmt.Sprintf("%x", h[:])
}

// buildConfig creates the ProtocolConfig for a single user given their key and node settings.
func buildConfig(key string, s NodeSettings) *sudokuapis.ProtocolConfig {
	var table *sudokutable.Table
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
		e.key = deriveKey(e.uuid, e.salt)
		e.cfg = buildConfig(e.key, s.settings)
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
		e.key = deriveKey(e.uuid, e.salt)
		e.cfg = buildConfig(e.key, s.settings)
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
		case httpmask.HandlePassThrough:
			current = c
		default:
			return
		}
	}

	// ── Phase 1: buffer ──────────────────────────────────────────────────────
	// Set the handshake deadline on the raw conn so it propagates through any
	// WS/stream wrapper to the underlying TCP read.
	timeout := s.settings.HandshakeTimeout
	if timeout <= 0 {
		timeout = 10
	}
	rawConn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))

	handshakeBytes, err := readHandshakeBytes(current, rawConn)

	// Restore deadline regardless of outcome; Phase 3 will set its own.
	rawConn.SetReadDeadline(time.Time{})

	if err != nil && len(handshakeBytes) == 0 {
		s.log.Debug("no handshake data received", "remote", rawConn.RemoteAddr(), "err", err)
		return
	}
	if len(handshakeBytes) == 0 {
		s.log.Debug("empty handshake, dropping", "remote", rawConn.RemoteAddr())
		return
	}

	// ── Phase 2: identify ────────────────────────────────────────────────────
	// Try each user's config against an in-memory sinkConn.
	// ServerHandshakeCore does: HTTP-mask peek → table probe → AEAD decrypt
	// client-hello → write server-hello (discarded) → return.
	// It does NOT read the session/OpenTCP message, so it completes entirely
	// within the already-buffered bytes.
	matchedIndex := -1
	for i, user := range users {
		probeCfg := user.cfg
		if disableInnerHTTPMask {
			inner := *user.cfg
			inner.DisableHTTPMask = true
			probeCfg = &inner
		}

		probe := newSinkConn(handshakeBytes, rawConn)
		result, probeErr := sudokuapis.ServerHandshakeCore(probe, probeCfg)
		if result != nil {
			_ = result.Conn.Close() // release any internal state
		}

		fmt.Printf("[sudoku-debug] PROBE %s index=%d user_id=%d buf=%d err=%v\n",
			map[bool]string{true: "SUCCESS", false: "FAIL"}[probeErr == nil],
			i, user.id, len(handshakeBytes), probeErr)

		if probeErr == nil {
			matchedIndex = i
			break
		}
	}

	if matchedIndex < 0 {
		s.log.Debug("all user configs exhausted, dropping connection", "remote", rawConn.RemoteAddr())
		return
	}

	// ── Phase 3: real handshake ───────────────────────────────────────────────
	// Replay the buffered bytes on top of the real connection and run the full
	// handshake + session-message read for the matched user.
	matchedUser := users[matchedIndex]
	realCfg := matchedUser.cfg
	if disableInnerHTTPMask {
		inner := *matchedUser.cfg
		inner.DisableHTTPMask = true
		realCfg = &inner
	}

	// NewPreBufferedConn serves handshakeBytes first, then reads from current.
	// The library re-reads the client hello from the buffer, sends the real
	// server hello over current, then reads the OpenTCP/UoT message from the
	// live connection — exactly the correct sequence.
	preBuffered := sudokuapis.NewPreBufferedConn(current, handshakeBytes)
	conn, session, targetAddr, _, _, err := sudokuapis.ServerHandshakeSessionAutoWithUserHash(preBuffered, realCfg)
	if err != nil {
		s.log.Debug("real handshake failed after probe match",
			"user_id", matchedUser.id, "err", err)
		return
	}

	s.proxy(conn, session, targetAddr, matchedUser)
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
			s.log.Error("dial target failed", "target", targetAddr, "uuid", user.uuid, "err", err)
			return
		}
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
