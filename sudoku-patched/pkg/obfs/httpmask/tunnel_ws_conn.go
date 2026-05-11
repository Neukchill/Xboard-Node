package httpmask

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// wsMessageConn wraps websocket.NetConn and exposes an extra helper for
// server-side callers that need to consume exactly one WebSocket message
// without reading into the next one.
//
// Normal Read/Write semantics remain delegated to websocket.NetConn so the
// rest of the tunnel continues to behave like a byte stream.
type wsMessageConn struct {
	net.Conn
	ws *websocket.Conn

	readMu sync.Mutex
}

// HTTPMaskReadMessage reads exactly one WebSocket message payload.
//
// Unlike websocket.NetConn.Read(), this call stops at the end of the current
// WS message instead of blocking for the next one. This is required by the
// Sudoku multi-user server, which must buffer only the first client-hello
// message before writing server hello back to the client.
func (c *wsMessageConn) HTTPMaskReadMessage(maxBytes int, timeout time.Duration) ([]byte, error) {
	if c == nil || c.ws == nil {
		return nil, fmt.Errorf("nil websocket conn")
	}
	if maxBytes <= 0 {
		maxBytes = 32 * 1024
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	ctx := context.Background()
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	msgType, r, err := c.ws.Reader(ctx)
	if err != nil {
		return nil, err
	}
	if msgType != websocket.MessageBinary {
		return nil, fmt.Errorf("unexpected websocket message type: %v", msgType)
	}

	var out bytes.Buffer
	out.Grow(min(maxBytes, 4096))
	tmp := make([]byte, 4096)
	overflow := false
	for out.Len() < maxBytes {
		n, readErr := r.Read(tmp)
		if n > 0 {
			if !overflow {
				if out.Len()+n > maxBytes {
					remain := maxBytes - out.Len()
					if remain > 0 {
						out.Write(tmp[:remain])
					}
					overflow = true
				} else {
					out.Write(tmp[:n])
				}
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				if overflow {
					return nil, fmt.Errorf("websocket message too large")
				}
				return out.Bytes(), nil
			}
			return nil, readErr
		}
	}

	for {
		_, readErr := r.Read(tmp)
		if readErr != nil {
			if readErr == io.EOF {
				return nil, fmt.Errorf("websocket message too large")
			}
			return nil, readErr
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
