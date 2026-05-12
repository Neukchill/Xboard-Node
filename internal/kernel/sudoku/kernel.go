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
	"sort"
	"strings"
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
	srv.UpdateUsers(specToEntries(users, settings))

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
	var settings NodeSettings
	if srv != nil {
		settings = srv.settings
	}
	k.mu.Unlock()
	if srv == nil {
		return 0, nil
	}
	added = srv.AddUsers(specToEntries(users, settings))
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
	var settings NodeSettings
	if srv != nil {
		settings = srv.settings
	}
	k.mu.Unlock()
	if srv == nil {
		return 0, 0, nil
	}
	added, removed = srv.UpdateUsers(specToEntries(users, settings))
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
	strSlice := func(key string) []string {
		if v, ok := ns[key]; ok {
			return strSliceFromAny(v)
		}
		return nil
	}

	return NodeSettings{
		TableType:          str("table_type", "up_ascii_down_entropy"),
		CustomTable:        str("custom_table", ""),
		CustomTables:       strSlice("custom_tables"),
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

func specToEntries(users []model.UserSpec, settings NodeSettings) []userEntry {
	out := make([]userEntry, 0, len(users))
	for _, u := range users {
		entry := userEntry{
			id:       u.ID,
			uuid:     u.UUID,
			salt:     settings.KeySalt,
			settings: settings,
		}
		applyUserOverrides(&entry)
		out = append(out, entry)
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

func strSliceFromAny(v any) []string {
	switch val := v.(type) {
	case []string:
		if len(val) == 0 {
			return nil
		}
		out := make([]string, 0, len(val))
		for _, item := range val {
			item = strings.TrimSpace(item)
			if item != "" {
				out = append(out, item)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	case []any:
		out := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				s = strings.TrimSpace(s)
				if s != "" {
					out = append(out, s)
				}
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	default:
		return nil
	}
}

func cloneExtras(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func extraString(extras map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := extras[key]; ok {
			if s, ok := v.(string); ok {
				s = strings.TrimSpace(s)
				if s != "" {
					return s
				}
			}
		}
	}
	return ""
}

func extraInt(extras map[string]any, keys ...string) (int, bool) {
	for _, key := range keys {
		if v, ok := extras[key]; ok {
			switch n := v.(type) {
			case int:
				return n, true
			case int64:
				return int(n), true
			case float64:
				return int(n), true
			}
		}
	}
	return 0, false
}

func extraBool(extras map[string]any, keys ...string) (bool, bool) {
	for _, key := range keys {
		if v, ok := extras[key]; ok {
			if b, ok := v.(bool); ok {
				return b, true
			}
		}
	}
	return false, false
}

func extraStringSlice(extras map[string]any, keys ...string) []string {
	for _, key := range keys {
		if v, ok := extras[key]; ok {
			if values := strSliceFromAny(v); len(values) > 0 {
				return values
			}
		}
	}
	return nil
}

func applyUserOverrides(entry *userEntry) {
	if entry == nil || len(entry.extras) == 0 {
		return
	}

	if rawKey := extraString(entry.extras,
		"key", "psk", "password", "sudoku_key", "protocol_key", "raw_key",
	); rawKey != "" {
		entry.key = rawKey
	}
	if salt := extraString(entry.extras,
		"key_salt", "salt", "user_key_salt", "sudoku_key_salt",
	); salt != "" {
		entry.salt = salt
	}

	if tableType := extraString(entry.extras,
		"table_type", "ascii_mode", "mode",
	); tableType != "" {
		entry.settings.TableType = tableType
	}
	if customTable := extraString(entry.extras,
		"custom_table", "table_pattern",
	); customTable != "" {
		entry.settings.CustomTable = customTable
	}
	if customTables := extraStringSlice(entry.extras,
		"custom_tables", "table_patterns",
	); len(customTables) > 0 {
		entry.settings.CustomTables = customTables
	}
	if aead := extraString(entry.extras,
		"aead_method", "aead", "cipher",
	); aead != "" {
		entry.settings.AEADMethod = aead
	}
	if v, ok := extraInt(entry.extras, "padding_min"); ok {
		entry.settings.PaddingMin = v
	}
	if v, ok := extraInt(entry.extras, "padding_max"); ok {
		entry.settings.PaddingMax = v
	}
	if v, ok := extraBool(entry.extras, "enable_pure_downlink"); ok {
		entry.settings.EnablePureDownlink = v
	}
	if v := extraString(entry.extras, "httpmask_mode"); v != "" {
		entry.settings.HTTPMaskMode = v
	}
	if v := extraString(entry.extras, "httpmask_path_root"); v != "" {
		entry.settings.HTTPMaskPathRoot = v
	}
	if v := extraString(entry.extras, "httpmask_multiplex"); v != "" {
		entry.settings.HTTPMaskMux = v
	}
}

func debugExtraKeys(extras map[string]any) string {
	if len(extras) == 0 {
		return ""
	}
	keys := make([]string, 0, len(extras))
	for key := range extras {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}
