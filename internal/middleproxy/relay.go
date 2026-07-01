package middleproxy

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	rpcProxyReq = 0xeef1ce36
	rpcProxyAns = 0x0dda0344
	rpcSimpleAck = 0x9b40ac3b
)

type proxyConnOpts struct {
	ClientIP   string
	ClientPort int
	LocalIP    string
	LocalPort  int
	AdTag      []byte
}

type proxyConn struct {
	relay *relayConn
	opts  proxyConnOpts
	connID [8]byte
}

func newProxyConn(relay *relayConn, opts proxyConnOpts) net.Conn {
	var id [8]byte
	_, _ = rand.Read(id[:])
	return &proxyConn{relay: relay, opts: opts, connID: id}
}

func (c *proxyConn) Read(p []byte) (int, error) {
	for len(c.relay.readBuf) == 0 {
		frame, err := readFrame(c.relay.cbc, &c.relay.seqNo)
		if err != nil {
			return 0, err
		}
		data, err := parseProxyAns(frame)
		if err != nil {
			return 0, err
		}
		if data == nil {
			continue
		}
		c.relay.readBuf = data
	}
	n := copy(p, c.relay.readBuf)
	c.relay.readBuf = c.relay.readBuf[n:]
	return n, nil
}

func (c *proxyConn) Write(p []byte) (int, error) {
	if len(p)%4 != 0 {
		return 0, fmt.Errorf("middleproxy: длина сообщения должна быть кратна 4")
	}
	msg := buildProxyReq(p, c.opts, c.connID[:])
	if err := writeFrame(c.relay.cbc, c.relay.seqNo, msg); err != nil {
		return 0, err
	}
	c.relay.seqNo++
	return len(p), nil
}

func (c *proxyConn) Close() error {
	return c.relay.raw.Close()
}

func (c *proxyConn) LocalAddr() net.Addr  { return c.relay.raw.LocalAddr() }
func (c *proxyConn) RemoteAddr() net.Addr { return c.relay.raw.RemoteAddr() }
func (c *proxyConn) SetDeadline(t time.Time) error {
	return c.relay.raw.SetDeadline(t)
}
func (c *proxyConn) SetReadDeadline(t time.Time) error {
	return c.relay.raw.SetReadDeadline(t)
}
func (c *proxyConn) SetWriteDeadline(t time.Time) error {
	return c.relay.raw.SetWriteDeadline(t)
}

func parseProxyAns(frame []byte) ([]byte, error) {
	if len(frame) < 4 {
		return nil, io.EOF
	}
	typ := binary.LittleEndian.Uint32(frame[:4])
	switch typ {
	case rpcProxyAns:
		if len(frame) < 16 {
			return nil, fmt.Errorf("короткий RPC_PROXY_ANS")
		}
		return frame[16:], nil
	case rpcSimpleAck:
		return nil, nil
	default:
		return nil, nil
	}
}

func buildProxyReq(payload []byte, opts proxyConnOpts, connID []byte) []byte {
	const (
		flagMagic        = 0x1000
		flagExtMode2     = 0x20000
		flagIntermediate = 0x20000000
		flagPad          = 0x8000000
		flagHasAdTag     = 0x8
		flagNotEncrypted = 0x2
	)

	flags := uint32(flagMagic | flagExtMode2 | flagIntermediate | flagPad)
	if len(payload) >= 8 && payload[0] == 0 && payload[1] == 0 && payload[2] == 0 && payload[3] == 0 &&
		payload[4] == 0 && payload[5] == 0 && payload[6] == 0 && payload[7] == 0 {
		flags |= flagNotEncrypted
	}
	if len(opts.AdTag) == 16 {
		flags |= flagHasAdTag
	}

	msg := make([]byte, 0, 64+len(payload))
	msg = append(msg, u32le(rpcProxyReq)...)
	flagsBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(flagsBytes, flags)
	msg = append(msg, flagsBytes...)
	msg = append(msg, connID...)
	msg = append(msg, encodeIPPort(opts.ClientIP, opts.ClientPort)...)
	msg = append(msg, encodeIPPort(opts.LocalIP, opts.LocalPort)...)

	if len(opts.AdTag) == 16 {
		msg = append(msg, 0x18, 0, 0, 0)
		msg = append(msg, 0xae, 0x26, 0x1e, 0xdb)
		msg = append(msg, byte(len(opts.AdTag)))
		msg = append(msg, opts.AdTag...)
		msg = append(msg, 0, 0, 0)
	}

	return append(msg, payload...)
}

func encodeIPPort(host string, port int) []byte {
	ip := net.ParseIP(host)
	out := make([]byte, 16)
	if ip4 := ip.To4(); ip4 != nil {
		copy(out[:10], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
		out[10] = 0xff
		out[11] = 0xff
		copy(out[12:], ip4)
	} else if ip16 := ip.To16(); ip16 != nil && ip.To4() == nil {
		copy(out[:16], ip16)
	}
	portBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(portBytes, uint32(port))
	return append(out, portBytes...)
}
