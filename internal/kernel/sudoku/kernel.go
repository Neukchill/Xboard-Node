// Package sudoku implements a Xboard-Node kernel for the official Sudoku proxy protocol.
// It wraps github.com/SUDOKU-ASCII/sudoku/apis to provide full compatibility with
// Mihomo-based clients (Clash Verge, FlClash, etc.).
//
// Multi-user design:
//   - Each user's key  = hex(sha256(uuid + key_salt))          (64 hex chars)
//   - Each user's table = sudoku.NewTable(key, table_type)
//   - Per-connection auth: sequential config probing with HandshakeError replay
//   - Traffic counted per user-id via relay byte counters
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
type Kernel struct {
	mu       sync.Mutex
	server   *Server
	running  bool
	log      *slog.Logger
	speedFn  func(uuid string) *rate.Limiter
	deviceFn func(uuid string) (int, bool)
}

// New creates a new Sudoku kernel instance.
func New() *Kernel {
	return &Kernel{
		log: slog.Default().With("kernel", "sudoku"),
	}
}

// ─── Identity ─────────────────────────────────────────────────────────────────

func (k *Kernel) Name() string        { return "sudoku" }
func (k *Kernel) Protocols() []string { return []string{"sudoku"} }
func (k *Kernel) Capabilities() kernel.Capabilities {
	return kernel.Capabilities{
		PerUserSpeedLimit:   false,
		DeviceLimit:         false,
		BuiltInTrafficStats: true,
		AliveIPTracking:     true,
		ForceCloseUser:      true,
	}
}

// ─── Lifecycle ────────────────────────────────────────────────────────────────

func (k *Kernel) Start(nc *model.NodeSpec, users []model.UserSpec, tlsCert kernel.TLSCert) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.running {
		k.stopLocked()
	}

	settings := settingsFromNodeSpec(nc)

	// TLS listener wrapping (optional)
	if tlsCert.HasCert() {
		cert, err := tls.X509KeyPair(tlsCert.CertPEM, tlsCert.KeyPEM)
		if err != nil {
			return fmt.Errorf("sudoku kernel: TLS keypair: %w", err)
		}
		settings.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
	}

	listenIP := nc.ListenIP
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	settings.Listen = fmt.Sprintf("%s:%d", listenIP, nc.ServerPort)

	srv := NewServer(settings, k.log)
	srv.UpdateUsers(specToEntries(users, settings.KeySalt))

	if err := srv.Start(); err != nil {
		return err
	}

	k.server = srv
	k.running = true
	k.log.Info("kernel started", "listen", settings.Listen, "users", len(users))
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

func (k *Kernel) Reload(nc *model.NodeSpec, users []model.UserSpec, tlsCert kernel.TLSCert) error {
	return k.Start(nc, users, tlsCert)
}

// ─── User management ──────────────────────────────────────────────────────────

func (k *Kernel) AddUsers(users []model.UserSpec) (added int, err error) {
	k.mu.Lock()
	srv := k.server
	salt := ""
	if srv != nil {
		salt = srv.settings.KeySalt
	}
	k.mu.Unlock()
	if srv == nil {
		return 0, nil
	}
	added = srv.AddUsers(specToEntries(users, salt))
	return
}

func (k *Kernel) RemoveUsers(users []model.UserSpec) (removed int, err error) {
	k.mu.Lock()
	srv := k.server
	k.mu.Unlock()
	if srv == nil {
		return 0, nil
	}
	removed = srv.RemoveUsers(specToIDs(users))
	return
}

func (k *Kernel) UpdateUsers(users []model.UserSpec) (added, removed int, err error) {
	k.mu.Lock()
	srv := k.server
	salt := ""
	if srv != nil {
		salt = srv.settings.KeySalt
	}
	k.mu.Unlock()
	if srv == nil {
		return 0, 0, nil
	}
	added, removed = srv.UpdateUsers(specToEntries(users, salt))
	return
}

// ─── Observability ────────────────────────────────────────────────────────────

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

func (k *Kernel) CloseConnection(_ context.Context, _ string) error { return nil }

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
}

func (k *Kernel) SetDeviceLimitFunc(fn func(uuid string) (int, bool)) {
	k.mu.Lock()
	k.deviceFn = fn
	k.mu.Unlock()
}

func (k *Kernel) UpdateGlobalDevices(_ map[int][]string) {}
func (k *Kernel) ClearGlobalDevices()                    {}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// settingsFromNodeSpec extracts Sudoku-specific settings from the NodeSpec.
// They arrive via NetworkSettings (set by the panel's buildNodeConfig).
func settingsFromNodeSpec(nc *model.NodeSpec) NodeSettings {
	ns := nc.NetworkSettings
	if ns == nil {
		ns = map[string]any{}
	}

	str := func(key, def string) string {
		if v, ok := ns[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
		return def
	}
	num := func(key string, def int) int {
		if v, ok := ns[key]; ok {
			switch n := v.(type) {
			case int:
				return n
			case float64:
				return int(n)
			case int64:
				return int(n)
			}
		}
		return def
	}
	bl := func(key string, def bool) bool {
		if v, ok := ns[key]; ok {
			if b, ok := v.(bool); ok {
				return b
			}
		}
		return def
	}

	return NodeSettings{
		TableType:          str("table_type", "up_ascii_down_entropy"),
		CustomTable:        str("custom_table", ""),
		AEADMethod:         str("aead_method", "chacha20-poly1305"),
		PaddingMin:         num("padding_min", 2),
		PaddingMax:         num("padding_max", 7),
		EnablePureDownlink: bl("enable_pure_downlink", false),
		HTTPMaskMode:       str("httpmask_mode", "legacy"),
		HTTPMaskPathRoot:   str("httpmask_path_root", ""),
		HTTPMaskMux:        str("httpmask_multiplex", "off"),
		KeySalt:            str("key_salt", ""),
		HandshakeTimeout:   10,
	}
}

func specToEntries(users []model.UserSpec, salt string) []userEntry {
	out := make([]userEntry, 0, len(users))
	for _, u := range users {
		out = append(out, userEntry{id: u.ID, uuid: u.UUID, salt: salt})
	}
	return out
}

func specToIDs(users []model.UserSpec) []int {
	out := make([]int, 0, len(users))
	for _, u := range users {
		out = append(out, u.ID)
	}
	return out
}
