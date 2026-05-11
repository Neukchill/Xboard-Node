package sudoku

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
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
	key  string // derived: hex(sha256(uuid+salt))
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

// handleConn authenticates an incoming connection using incremental probing.
//
// Design (v5):
//
//	After the optional HTTP-mask / WebSocket upgrade, we read bytes from the
//	upgraded connection in small chunks and, after each chunk, probe every
//	registered user with ProbeHandshakeDetailed. We stop reading as soon as
//	one user matches, OR when all users definitively reject the bytes. Then
//	we replay the buffered bytes via NewPreBufferedConn and run the full
//	server handshake on the real connection for the matched user only.
//
// Why incremental (and why the earlier "buffer everything first" approach
// broke in WebSocket mode):
//
//	The conn returned by httpmask in WS mode is a coder/websocket NetConn.
//	Two facts about that NetConn make naive buffering unsafe:
//
//	  1. Read() never returns io.EOF at message boundaries — it silently
//	     fetches the next message, blocking if none has arrived.  We cannot
//	     detect "client-hello fully buffered" by reading until EOF.
//
//	  2. SetReadDeadline triggers a context cancellation inside coder/websocket
//	     that the library treats as a permanent connection failure.  Once it
//	     fires, every subsequent Read/Write returns "use of closed network
//	     connection", even though the underlying TCP socket is still alive.
//
//	The incremental probe loop terminates the moment a user matches, so we
//	never make a Read past the end of the client-hello message and never need
//	a deadline on the NetConn.  A watchdog goroutine hard-closes the underlying
//	rawConn after HandshakeTimeout, providing an upper bound on probe time
//	without poisoning the WS state.
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

	// ── Phase 1+2: incremental multi-user probe ──────────────────────────────
	timeout := s.settings.HandshakeTimeout
	if timeout <= 0 {
		timeout = 10
	}

	// Timeout strategy:
	//   TCP/TLS mode → SetReadDeadline on rawConn (safe, classic semantics).
	//   WS  mode     → watchdog goroutine that hard-closes rawConn on timeout.
	//                  Setting any deadline on the WS NetConn would cancel its
	//                  read context, which coder/websocket treats as a permanent
	//                  failure — every subsequent Write would return
	//                  "use of closed network connection".
	var cancelProbe context.CancelFunc
	if disableInnerHTTPMask {
		var probeCtx context.Context
		probeCtx, cancelProbe = context.WithTimeout(s.ctx, time.Duration(timeout)*time.Second)
		go func(ctx context.Context) {
			<-ctx.Done()
			if ctx.Err() == context.DeadlineExceeded {
				_ = rawConn.Close()
			}
		}(probeCtx)
	} else {
		_ = rawConn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	}

	const (
		maxProbeBytes = 64 * 1024
		readChunk     = 4 * 1024
	)
	tmp := make([]byte, readChunk)
	var probeBytes []byte
	matchedIndex := -1

probeLoop:
	for {
		// Try every user with the bytes we have so far.
		needMore := false
		for i, user := range users {
			probeCfg := user.cfg
			if disableInnerHTTPMask {
				inner := *user.cfg
				inner.DisableHTTPMask = true
				probeCfg = &inner
			}
			err := sudokuapis.ProbeHandshakeDetailed(probeBytes, probeCfg)
			if err == nil {
				matchedIndex = i
				fmt.Printf("[sudoku-debug] PROBE SUCCESS index=%d user_id=%d buf=%d\n",
					i, user.id, len(probeBytes))
				break probeLoop
			}
			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
				needMore = true
			}
		}
		if !needMore {
			fmt.Printf("[sudoku-debug] PROBE EXHAUSTED buf=%d remote=%s (all users rejected)\n",
				len(probeBytes), rawConn.RemoteAddr())
			break
		}
		if len(probeBytes) >= maxProbeBytes {
			fmt.Printf("[sudoku-debug] PROBE MAX BYTES buf=%d remote=%s\n",
				len(probeBytes), rawConn.RemoteAddr())
			break
		}
		n, err := current.Read(tmp)
		if n > 0 {
			probeBytes = append(probeBytes, tmp[:n]...)
		}
		if err != nil {
			fmt.Printf("[sudoku-debug] PROBE READ ERR buf=%d remote=%s err=%v\n",
				len(probeBytes), rawConn.RemoteAddr(), err)
			break
		}
	}

	// Stop the watchdog (Phase 3 manages its own deadlines) and reset any
	// TCP-mode read deadline before continuing.
	if cancelProbe != nil {
		cancelProbe()
	}
	if !disableInnerHTTPMask {
		_ = rawConn.SetReadDeadline(time.Time{})
	}

	if matchedIndex < 0 {
		return
	}

	// ── Phase 3: real handshake ───────────────────────────────────────────────
	matchedUser := users[matchedIndex]
	realCfg := matchedUser.cfg
	if disableInnerHTTPMask {
		inner := *matchedUser.cfg
		inner.DisableHTTPMask = true
		realCfg = &inner
	}

	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[sudoku-debug] PHASE3 PANIC user_id=%d r=%v\n", matchedUser.id, r)
		}
	}()

	fmt.Printf("[sudoku-debug] PHASE3 BEGIN user_id=%d buf=%d remote=%s\n",
		matchedUser.id, len(probeBytes), rawConn.RemoteAddr())

	preBuffered := sudokuapis.NewPreBufferedConn(current, probeBytes)
	conn, session, targetAddr, _, _, err := sudokuapis.ServerHandshakeSessionAutoWithUserHash(preBuffered, realCfg)
	if err != nil {
		fmt.Printf("[sudoku-debug] PHASE3 HANDSHAKE FAIL user_id=%d err=%v\n",
			matchedUser.id, err)
		return
	}

	fmt.Printf("[sudoku-debug] PHASE3 HANDSHAKE OK user_id=%d session=%v target=%s\n",
		matchedUser.id, session, targetAddr)

	s.proxy(conn, session, targetAddr, matchedUser)

	fmt.Printf("[sudoku-debug] PHASE3 PROXY EXITED user_id=%d target=%s\n",
		matchedUser.id, targetAddr)
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
			fmt.Printf("[sudoku-debug] DIAL TARGET FAIL target=%s user_id=%d err=%v\n",
				targetAddr, user.id, err)
			s.log.Error("dial target failed", "target", targetAddr, "uuid", user.uuid, "err", err)
			return
		}
		fmt.Printf("[sudoku-debug] DIAL TARGET OK target=%s user_id=%d\n", targetAddr, user.id)
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
