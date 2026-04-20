package sudoku

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync"

	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"golang.org/x/time/rate"
)

// Kernel implements kernel.Kernel for the Sudoku protocol.
// It runs a native Go TCP proxy server – no sing-box or xray needed.
type Kernel struct {
	mu      sync.Mutex
	server  *Server
	running bool
	log     *slog.Logger

	speedFn  func(uuid string) *rate.Limiter
	deviceFn func(uuid string) (int, bool)
}

// New creates a new Sudoku kernel. The KernelConfig is accepted for interface
// compatibility but only the log-level field is used.
func New() *Kernel {
	return &Kernel{
		log: slog.Default().With("kernel", "sudoku"),
	}
}

// ─── Identity ────────────────────────────────────────────────────────────────

func (k *Kernel) Name() string            { return "sudoku" }
func (k *Kernel) Protocols() []string     { return []string{"sudoku"} }
func (k *Kernel) Capabilities() kernel.Capabilities {
	return kernel.Capabilities{
		PerUserSpeedLimit:   false, // could be extended later
		DeviceLimit:         false,
		BuiltInTrafficStats: true,
		AliveIPTracking:     true,
		ForceCloseUser:      true,
	}
}

// ─── Lifecycle ────────────────────────────────────────────────────────────────

func (k *Kernel) Start(nc *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.running {
		k.stopLocked()
	}

	tlsCfg, err := buildTLS(tls)
	if err != nil {
		return fmt.Errorf("sudoku kernel: build TLS: %w", err)
	}

	listenAddr := fmt.Sprintf("%s:%d", nc.ListenIP, nc.ServerPort)
	if nc.ListenIP == "" {
		listenAddr = fmt.Sprintf("0.0.0.0:%d", nc.ServerPort)
	}

	srv := NewServer(ServerConfig{
		Listen:    listenAddr,
		TLSConfig: tlsCfg,
	}, k.log)

	// Load users before starting so the first connection can auth.
	srv.UpdateUsers(specToEntries(users))

	if err := srv.Start(); err != nil {
		return err
	}

	k.server = srv
	k.running = true
	k.log.Info("kernel started", "listen", listenAddr, "users", len(users))
	return nil
}

func (k *Kernel) Stop() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.stopLocked()
}

func (k *Kernel) stopLocked() {
	if !k.running || k.server == nil {
		return
	}
	k.server.Stop()
	k.server = nil
	k.running = false
	k.log.Info("kernel stopped")
}

func (k *Kernel) IsRunning() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.running
}

func (k *Kernel) Reload(nc *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	// For a port change we must restart. For a user-only change, UpdateUsers is
	// called separately. Full restart is always safe.
	return k.Start(nc, users, tls)
}

// ─── User management ─────────────────────────────────────────────────────────

func (k *Kernel) AddUsers(users []model.UserSpec) (added int, err error) {
	k.mu.Lock()
	srv := k.server
	k.mu.Unlock()

	if srv == nil {
		return 0, nil
	}
	added = srv.AddUsers(specToEntries(users))
	return
}

func (k *Kernel) RemoveUsers(users []model.UserSpec) (removed int, err error) {
	k.mu.Lock()
	srv := k.server
	k.mu.Unlock()

	if srv == nil {
		return 0, nil
	}
	removed = srv.RemoveUsers(specToEntries(users))
	return
}

func (k *Kernel) UpdateUsers(users []model.UserSpec) (added, removed int, err error) {
	k.mu.Lock()
	srv := k.server
	k.mu.Unlock()

	if srv == nil {
		return 0, 0, nil
	}
	added, removed = srv.UpdateUsers(specToEntries(users))
	return
}

// ─── Observability ───────────────────────────────────────────────────────────

func (k *Kernel) GetUserTraffic(_ context.Context) (
	traffic map[int][2]int64,
	aliveIPs map[int]map[string]bool,
	connCount int,
	err error,
) {
	k.mu.Lock()
	srv := k.server
	k.mu.Unlock()

	if srv == nil {
		return nil, nil, 0, nil
	}
	traffic = srv.GetTraffic()
	aliveIPs = srv.GetAliveIPs()
	connCount = srv.ActiveConnCount()
	return
}

func (k *Kernel) CloseConnection(_ context.Context, _ string) error {
	// Per-connection close by ID is not implemented; use CloseUserConnections.
	return nil
}

func (k *Kernel) CloseUserConnections(_ context.Context, uuid string) error {
	k.mu.Lock()
	srv := k.server
	k.mu.Unlock()

	if srv != nil {
		srv.CloseUserConns(uuid)
	}
	return nil
}

func (k *Kernel) SetSpeedLimitFunc(fn func(uuid string) *rate.Limiter) {
	k.mu.Lock()
	k.speedFn = fn
	k.mu.Unlock()
	// Speed limiting via rate.Limiter wrapping io.Copy is not implemented in
	// the first version. The field is stored for future use.
}

func (k *Kernel) SetDeviceLimitFunc(fn func(uuid string) (int, bool)) {
	k.mu.Lock()
	k.deviceFn = fn
	k.mu.Unlock()
}

func (k *Kernel) UpdateGlobalDevices(_ map[int][]string) {} // no-op in single-node mode
func (k *Kernel) ClearGlobalDevices()                     {} // no-op

// ─── Helpers ─────────────────────────────────────────────────────────────────

func specToEntries(users []model.UserSpec) []userEntry {
	out := make([]userEntry, 0, len(users))
	for _, u := range users {
		out = append(out, userEntry{id: u.ID, uuid: u.UUID})
	}
	return out
}

func buildTLS(t kernel.TLSCert) (*tls.Config, error) {
	if !t.HasCert() {
		return nil, nil
	}
	cert, err := tls.X509KeyPair(t.CertPEM, t.KeyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}, nil
}
