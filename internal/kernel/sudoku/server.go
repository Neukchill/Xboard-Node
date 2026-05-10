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

// replayableConn wraps a net.Conn and records every byte obtained from the
// underlying connection.  Calling Reset() rewinds the internal read cursor
// to zero so that subsequent Read calls replay the recorded bytes before
// continuing to read from the underlying conn.
//
// This is used in handleConn to allow multiple sequential Sudoku handshake
// probes (one per registered user) to each see the same incoming byte stream
// without having to re-establish the connection or chain PreBufferedConns.
type replayableConn struct {
	net.Conn
	buf []byte // bytes recorded from underlying Conn
	pos int    // current read position within buf
}

func newReplayableConn(c net.Conn) *replayableConn {
	return &replayableConn{Conn: c}
}

// Reset rewinds the read cursor to the beginning of the recorded buffer.
// The next Read will replay from byte 0.
func (r *replayableConn) Reset() { r.pos = 0 }

// Read satisfies io.Reader.  It serves bytes from the replay buffer first;
// once the buffer is exhausted it reads fresh bytes from the underlying
// Conn, appending them to the buffer so they can be replayed later.
func (r *replayableConn) Read(p []byte) (int, error) {
	if r.pos < len(r.buf) {
		n := copy(p, r.buf[r.pos:])
		r.pos += n
		return n, nil
	}
	n, err := r.Conn.Read(p)
	if n > 0 {
		r.buf = append(r.buf, p[:n]...)
		r.pos += n
	}
	return n, err
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
	// Initialize the HTTPMask tunnel server for non-legacy modes.
	// This handles the outer WebSocket / HTTP-tunnel upgrade before the
	// per-user Sudoku obfs handshake runs on the inner stream.
	switch strings.ToLower(strings.TrimSpace(s.settings.HTTPMaskMode)) {
	case "ws", "stream", "poll", "auto":
		s.httpmaskServer = httpmask.NewTunnelServer(httpmask.TunnelServerOptions{
			Mode:     s.settings.HTTPMaskMode,
			PathRoot: s.settings.HTTPMaskPathRoot,
			// AuthKey + EarlyHandshake are intentionally not set:
			//   - AuthKey is single-key anti-probing; multi-user nodes
			//     authenticate at the inner Sudoku layer instead.
			//   - EarlyHandshake binds to one user's PSK/Table; not usable
			//     for multi-user probing. The extra RTT is acceptable.
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
	// Populate derived key + config for each entry
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

// handleConn authenticates an incoming connection by sequentially trying each
// registered user's ProtocolConfig. On each failure, the HandshakeError carry
// the bytes already consumed, which are prepended to the raw connection for the
// next attempt (replay mechanism from the official API).
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

	// Determine the connection that will be handed to the inner Sudoku probe loop,
	// and whether the inner handshake should skip the HTTP-header peek.
	//
	// For ws / stream / poll / auto modes, the outer HTTPMask tunnel layer
	// (WebSocket Upgrade or HTTP tunnel framing) is processed first. Only after
	// that upgrade succeeds does the inner Sudoku obfs handshake run.
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
			// Tunnel server already handled and closed the connection
			// (e.g. poll control request, rejected probe).
			return
		case httpmask.HandleStartTunnel:
			// WS / stream upgrade succeeded. The returned conn carries the
			// raw Sudoku stream. The inner handshake must skip its own
			// HTTP-header peek because the bytes are already past that point.
			current = c
			disableInnerHTTPMask = true
		case httpmask.HandlePassThrough:
			// Not an HTTP tunnel request (or rejected with PassThroughOnReject).
			// The returned conn replays any pre-read bytes; fall through to
			// the legacy probe loop on it.
			current = c
		default:
			return
		}
	}

	// Wrap the logical stream in a replayableConn so every user probe reads
	// from exactly the same byte sequence.  replayableConn records every
	// byte obtained from the underlying connection; Reset() rewinds the read
	// cursor to zero so the next probe re-reads the identical bytes without
	// touching the underlying conn again.
	//
	// This replaces the old HandshakeError-based PreBufferedConn chain, which
	// broke in WS/tunnel mode because hsErr.RawConn referred to the raw TCP
	// layer rather than the decoded inner stream.
	replay := newReplayableConn(current)

	for _, user := range users {
		// Rewind so this probe sees the same bytes as every previous probe.
		replay.Reset()

		// When the outer WS/stream/poll layer already consumed the HTTP
		// part, clone the per-user cfg with DisableHTTPMask=true so that
		// the inner handshake doesn't try to peek for HTTP again on the
		// upgraded stream.
		probeCfg := user.cfg
		if disableInnerHTTPMask {
			inner := *user.cfg
			inner.DisableHTTPMask = true
			probeCfg = &inner
		}

		conn, session, targetAddr, _, _, err := sudokuapis.ServerHandshakeSessionAutoWithUserHash(replay, probeCfg)
		if err == nil {
			// Authenticated! Start proxying.
			s.proxy(conn, session, targetAddr, user)
			return
		}

		// If no bytes were buffered at all the underlying connection is
		// already dead; there is nothing to replay.
		if len(replay.buf) == 0 {
			s.log.Debug("connection closed before handshake data received",
				"remote", rawConn.RemoteAddr())
			return
		}
	}

	s.log.Debug("all user configs exhausted, dropping connection", "remote", rawConn.RemoteAddr())
}

// proxy relays traffic between the authenticated tunnel connection and the target.
func (s *Server) proxy(conn net.Conn, session sudokuapis.SessionKind, targetAddr string, user userEntry) {
	connID := conn.RemoteAddr().String()

	// Register live connection.
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
		// UDP-over-TCP: the Sudoku library handles framing internally.
		// We can't easily count per-packet bytes here; traffic will not be
		// attributed for UoT sessions in this version.
		if err := sudokuapis.HandleUoT(conn); err != nil {
			s.log.Debug("UoT session ended", "uuid", user.uuid, "err", err)
		}

	case sudokuapis.SessionMux:
		// Multiplexed session: use HandleMuxWithDialer to proxy sub-streams.
		err := sudokuapis.HandleMuxWithDialer(conn,
			func(addr string) { s.log.Debug("mux sub-stream", "uuid", user.uuid, "target", addr) },
			func(addr string) (net.Conn, error) {
				target, err := net.DialTimeout("tcp", addr, 10*time.Second)
				if err != nil {
					return nil, err
				}
				// Count traffic for each sub-connection.
				return &countingConn{Conn: target, userID: user.id, srv: s}, nil
			},
		)
		if err != nil {
			s.log.Debug("mux session ended", "uuid", user.uuid, "err", err)
		}

	default: // SessionForward
		// Standard TCP relay.
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
