package apis

import (
"fmt"

"github.com/SUDOKU-ASCII/sudoku/internal/tunnel"
)

// ProbeHandshake reports whether probe contains a valid Sudoku client hello
// for cfg. Pure in-memory operation — no goroutines, no network I/O.
func ProbeHandshake(probe []byte, cfg *ProtocolConfig) error {
if cfg == nil {
return fmt.Errorf("config is required")
}
if err := cfg.Validate(); err != nil {
return fmt.Errorf("invalid config: %w", err)
}
for _, table := range cfg.tableCandidates() {
for _, mode := range []tunnel.ObfsUplinkMode{
tunnel.ObfsUplinkPure,
tunnel.ObfsUplinkPacked,
} {
if probeHandshakeBytes(probe, cfg, table, mode) == nil {
return nil
}
}
}
return fmt.Errorf("probe: no matching key/table")
}
