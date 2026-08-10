package middleproxy

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"time"
)

const maxIntermediateLen = 1 << 20

// intermediateConn переводит padded intermediate (4-byte len + payload) в сырой MTProto
// для RPC_PROXY_REQ и обратно — как mtprotoproxy/telemt.
type intermediateConn struct {
	net.Conn
	wbuf    []byte
	readBuf []byte
}

func wrapIntermediate(conn net.Conn) net.Conn {
	return &intermediateConn{Conn: conn}
}

func (c *intermediateConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.wbuf = append(c.wbuf, p...)
	orig := len(p)

	for {
		payload, rest, ok, err := nextPaddedIntermediate(c.wbuf)
		if err != nil {
			return 0, err
		}
		if !ok {
			break
		}
		if len(payload)%4 != 0 {
			return 0, fmt.Errorf("middleproxy: padded intermediate payload %d не кратен 4", len(payload))
		}
		if _, err := c.Conn.Write(payload); err != nil {
			return 0, err
		}
		c.wbuf = rest
	}
	return orig, nil
}

func (c *intermediateConn) Read(p []byte) (int, error) {
	if len(c.readBuf) == 0 {
		inner, err := c.readOnePayload()
		if err != nil {
			return 0, err
		}
		frame := make([]byte, 4+len(inner))
		binary.LittleEndian.PutUint32(frame, uint32(len(inner)))
		copy(frame[4:], inner)
		c.readBuf = frame
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *intermediateConn) readOnePayload() ([]byte, error) {
	if pr, ok := c.Conn.(interface{ readPayload() ([]byte, error) }); ok {
		return pr.readPayload()
	}
	return nil, fmt.Errorf("middleproxy: Conn не поддерживает readPayload")
}

func (c *intermediateConn) CloseWrite() error {
	if len(c.wbuf) > 0 {
		slog.Debug("middleproxy: незавершённый padded intermediate при CloseWrite", "bytes", len(c.wbuf))
	}
	type halfCloser interface {
		CloseWrite() error
	}
	if hc, ok := c.Conn.(halfCloser); ok {
		return hc.CloseWrite()
	}
	return nil
}

func nextPaddedIntermediate(buf []byte) (payload, rest []byte, ok bool, err error) {
	if len(buf) < 4 {
		return nil, buf, false, nil
	}
	n := binary.LittleEndian.Uint32(buf[:4]) & 0x7fffffff
	if n == 0 || n > maxIntermediateLen {
		return nil, nil, false, fmt.Errorf("middleproxy: некорректная длина padded intermediate %d", n)
	}
	total := 4 + int(n)
	if len(buf) < total {
		return nil, buf, false, nil
	}
	return append([]byte(nil), buf[4:total]...), buf[total:], true, nil
}

func (c *intermediateConn) SetDeadline(t time.Time) error      { return c.Conn.SetDeadline(t) }
func (c *intermediateConn) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(t) }
func (c *intermediateConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(t) }
