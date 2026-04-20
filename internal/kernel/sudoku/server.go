package sudoku

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// userEntry stores everything we need for a live user.
type userEntry struct {
	id   int
	uuid string
}

// trafficCounter holds atomic upload / download byte counts for one user.
type trafficCounter struct {
	upload   atomic.Int64
	download atomic.Int64
}

// connRecord tracks a single live connection.
type connRecord struct {
	id     string // remote addr string used as identifier
	uuid   string
	client net.Conn
	target net.Conn
}

// ServerConfig is the runtime configuration for the Sudoku proxy server.
type ServerConfig struct {
	Listen    string     // e.g. "0.0.0.0:12345"
	TLSConfig *tls.Config // nil = plain TCP

	// Speed-limit callback (nil = no limit). Returns a token bucket limited
	// io.Writer; the server wraps uploads through it.
	SpeedLimitFn func(uuid string) (downloadBytesPerSec int64, ok bool)
}

// Server is the running Sudoku proxy server.
type Server struct {
	cfg      ServerConfig
	listener net.Listener
	log      *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc

	// user set (keyed by UUID for fast lookup during auth)
	usersMu  sync.RWMutex
	byUUID   map[string]userEntry // uuid → entry
	byID     map[int]userEntry    // id → entry

	// traffic counters (keyed by user id, created lazily)
	trafficMu sync.Mutex
	traffic   map[int]*trafficCounter

	// live connections
	connsMu sync.RWMutex
	conns   map[string]*connRecord

	// connection counter for metrics
	activeConns atomic.Int64
	totalConns  atomic.Int64
}

// NewServer creates a server but does not start it.
func NewServer(cfg ServerConfig, log *slog.Logger) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:     cfg,
		log:     log,
		ctx:     ctx,
		cancel:  cancel,
		byUUID:  make(map[string]userEntry),
		byID:    make(map[int]userEntry),
		traffic: make(map[int]*trafficCounter),
		conns:   make(map[string]*connRecord),
	}
}

// Start begins accepting connections. Non-blocking; returns once the
// listener is bound.
func (s *Server) Start() error {
	var ln net.Listener
	var err error

	if s.cfg.TLSConfig != nil {
		ln, err = tls.Listen("tcp", s.cfg.Listen, s.cfg.TLSConfig)
	} else {
		ln, err = net.Listen("tcp", s.cfg.Listen)
	}
	if err != nil {
		return fmt.Errorf("sudoku server: listen %s: %w", s.cfg.Listen, err)
	}
	s.listener = ln
	s.log.Info("sudoku server listening", "addr", s.cfg.Listen, "tls", s.cfg.TLSConfig != nil)

	go s.acceptLoop()
	return nil
}

// Stop shuts down the server gracefully.
func (s *Server) Stop() {
	s.cancel()
	if s.listener != nil {
		_ = s.listener.Close()
	}
	// Close all live connections.
	s.connsMu.Lock()
	for _, rec := range s.conns {
		_ = rec.client.Close()
		if rec.target != nil {
			_ = rec.target.Close()
		}
	}
	s.connsMu.Unlock()
}

// UpdateUsers atomically replaces the entire user set.
// Returns (added, removed) counts relative to the old set.
func (s *Server) UpdateUsers(users []userEntry) (added, removed int) {
	s.usersMu.Lock()
	defer s.usersMu.Unlock()

	newByUUID := make(map[string]userEntry, len(users))
	newByID := make(map[int]userEntry, len(users))
	for _, u := range users {
		newByUUID[u.uuid] = u
		newByID[u.id] = u
	}

	for uuid := range newByUUID {
		if _, exists := s.byUUID[uuid]; !exists {
			added++
		}
	}
	for uuid := range s.byUUID {
		if _, exists := newByUUID[uuid]; !exists {
			removed++
		}
	}

	s.byUUID = newByUUID
	s.byID = newByID
	return
}

// AddUsers registers additional users without touching the existing set.
// Returns the number actually added (duplicates skipped).
func (s *Server) AddUsers(users []userEntry) int {
	s.usersMu.Lock()
	defer s.usersMu.Unlock()

	added := 0
	for _, u := range users {
		if _, exists := s.byUUID[u.uuid]; !exists {
			s.byUUID[u.uuid] = u
			s.byID[u.id] = u
			added++
		}
	}
	return added
}

// RemoveUsers deregisters the given users. Active connections for removed
// users are closed. Returns the number actually removed.
func (s *Server) RemoveUsers(users []userEntry) int {
	s.usersMu.Lock()

	removed := 0
	var kickUUIDs []string
	for _, u := range users {
		if _, exists := s.byUUID[u.uuid]; exists {
			delete(s.byUUID, u.uuid)
			delete(s.byID, u.id)
			kickUUIDs = append(kickUUIDs, u.uuid)
			removed++
		}
	}
	s.usersMu.Unlock()

	// Close connections for removed users.
	for _, uuid := range kickUUIDs {
		s.closeUserConns(uuid)
	}
	return removed
}

// CloseUserConns closes all active connections for the given UUID.
func (s *Server) CloseUserConns(uuid string) {
	s.closeUserConns(uuid)
}

// closeUserConns is the internal (no lock on usersMu) implementation.
func (s *Server) closeUserConns(uuid string) {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()

	for id, rec := range s.conns {
		if rec.uuid == uuid {
			_ = rec.client.Close()
			if rec.target != nil {
				_ = rec.target.Close()
			}
			delete(s.conns, id)
		}
	}
}

// GetTraffic returns and resets per-user traffic counters.
// Returns map[userID → [upload, download]].
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

// GetAliveIPs returns per-user live source IPs.
// Returns map[userID → set of IP strings].
func (s *Server) GetAliveIPs() map[int]map[string]bool {
	s.connsMu.RLock()
	defer s.connsMu.RUnlock()

	out := make(map[int]map[string]bool)

	s.usersMu.RLock()
	defer s.usersMu.RUnlock()

	for _, rec := range s.conns {
		u, ok := s.byUUID[rec.uuid]
		if !ok {
			continue
		}
		if out[u.id] == nil {
			out[u.id] = make(map[string]bool)
		}
		host, _, err := net.SplitHostPort(rec.client.RemoteAddr().String())
		if err == nil {
			out[u.id][host] = true
		}
	}
	return out
}

// ActiveConnCount returns the current number of live proxied connections.
func (s *Server) ActiveConnCount() int {
	return int(s.activeConns.Load())
}

// ---- internal ---------------------------------------------------------------

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

func (s *Server) handleConn(clientConn net.Conn) {
	defer clientConn.Close()

	// 5-second handshake deadline.
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))

	s.usersMu.RLock()
	uuids := make([]string, 0, len(s.byUUID))
	for uuid := range s.byUUID {
		uuids = append(uuids, uuid)
	}
	s.usersMu.RUnlock()

	uuid, cmd, addr, err := ReadHandshake(clientConn, uuids)
	if err != nil {
		s.log.Debug("handshake failed", "remote", clientConn.RemoteAddr(), "err", err)
		_ = WriteReply(clientConn, RepAuthFail)
		return
	}

	if cmd != CmdTCP {
		_ = WriteReply(clientConn, RepCmdUnsupported)
		return
	}

	targetConn, err := net.DialTimeout("tcp", addr.String(), 10*time.Second)
	if err != nil {
		s.log.Error("dial target failed", "target", addr, "err", err)
		_ = WriteReply(clientConn, RepAuthFail)
		return
	}
	defer targetConn.Close()

	if err = WriteReply(clientConn, RepSuccess); err != nil {
		return
	}
	// Clear deadline for the data transfer phase.
	_ = clientConn.SetDeadline(time.Time{})

	// Register live connection.
	connID := clientConn.RemoteAddr().String()
	rec := &connRecord{id: connID, uuid: uuid, client: clientConn, target: targetConn}
	s.connsMu.Lock()
	s.conns[connID] = rec
	s.connsMu.Unlock()
	s.activeConns.Add(1)
	s.totalConns.Add(1)

	// Relay and count bytes.
	up, dn := relay(clientConn, targetConn)

	// Deregister.
	s.connsMu.Lock()
	delete(s.conns, connID)
	s.connsMu.Unlock()
	s.activeConns.Add(-1)

	// Accumulate traffic.
	s.usersMu.RLock()
	u, ok := s.byUUID[uuid]
	s.usersMu.RUnlock()
	if ok && (up > 0 || dn > 0) {
		s.trafficMu.Lock()
		c, exists := s.traffic[u.id]
		if !exists {
			c = &trafficCounter{}
			s.traffic[u.id] = c
		}
		s.trafficMu.Unlock()
		c.upload.Add(up)
		c.download.Add(dn)
	}
}

// relay copies data bidirectionally between client and target.
// Returns (client→target bytes, target→client bytes).
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
