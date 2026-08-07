package middleproxy

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"time"
)

var (
	rpcNonceTag     = []byte{0xaa, 0x87, 0xcb, 0x7a}
	rpcHandshakeTag = []byte{0xf5, 0xee, 0x82, 0x76}
	cryptoAESTag    = []byte{0x01, 0x00, 0x00, 0x00}
)

const (
	startSeqNo = int32(-2)
	nonceLen   = 16
)

// DialOpts — параметры подключения через middle proxy.
type DialOpts struct {
	DCID         int
	ClientIP     string
	ClientPort   int
	LocalIP      string
	AdTag        []byte
	ProxySecret  []byte
	DialTimeout  time.Duration
}

// Dial устанавливает соединение с Telegram через middle proxy.
func Dial(ctx context.Context, opts DialOpts) (net.Conn, error) {
	if len(opts.ProxySecret) == 0 {
		opts.ProxySecret = DefaultProxySecret
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 10 * time.Second
	}

	endpoints := ResolveEndpoints(opts.DCID)
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("нет middle proxy для DC %d", opts.DCID)
	}

	var lastErr error
	for _, ep := range endpoints {
		conn, err := dialEndpoint(ctx, ep, opts)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("не удалось подключиться к middle proxy")
	}
	return nil, lastErr
}

func dialEndpoint(ctx context.Context, ep Endpoint, opts DialOpts) (net.Conn, error) {
	d := net.Dialer{Timeout: opts.DialTimeout}
	raw, err := d.DialContext(ctx, "tcp", ep.String())
	if err != nil {
		return nil, err
	}

	tcp, ok := raw.(*net.TCPConn)
	if !ok {
		_ = raw.Close()
		return nil, fmt.Errorf("ожидался TCP")
	}

	localIP := opts.LocalIP
	if localIP == "" {
		localIP = localIPv4(tcp)
	}
	if localIP == "" {
		_ = tcp.Close()
		return nil, fmt.Errorf("не удалось определить local IP для middle proxy")
	}

	relay, err := handshake(tcp, opts.ProxySecret, localIP)
	if err != nil {
		_ = tcp.Close()
		return nil, err
	}

	return newProxyConn(relay, proxyConnOpts{
		ClientIP:   opts.ClientIP,
		ClientPort: opts.ClientPort,
		LocalIP:    localIP,
		LocalPort:  localPort(tcp),
		AdTag:      opts.AdTag,
	}), nil
}

type relayConn struct {
	raw      net.Conn
	cbc      *cbcConn
	readSeq  int32
	writeSeq int32
	readBuf  []byte
}

func handshake(raw net.Conn, secret []byte, localIP string) (*relayConn, error) {
	keySelector := secret[:4]
	cryptoTS := make([]byte, 4)
	binary.LittleEndian.PutUint32(cryptoTS, uint32(time.Now().Unix()))

	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	nonceMsg := make([]byte, 0, 32)
	nonceMsg = append(nonceMsg, rpcNonceTag...)
	nonceMsg = append(nonceMsg, keySelector...)
	nonceMsg = append(nonceMsg, cryptoAESTag...)
	nonceMsg = append(nonceMsg, cryptoTS...)
	nonceMsg = append(nonceMsg, nonce...)

	readSeq := startSeqNo
	writeSeq := startSeqNo
	if err := writeFrame(raw, writeSeq, nonceMsg); err != nil {
		return nil, fmt.Errorf("RPC_NONCE: %w", err)
	}
	writeSeq++

	ans, err := readFrame(raw, &readSeq)
	if err != nil {
		return nil, fmt.Errorf("RPC_NONCE ans: %w", err)
	}
	if len(ans) != 32 {
		return nil, fmt.Errorf("RPC_NONCE ans len=%d", len(ans))
	}
	if !bytesEqual(ans[:4], rpcNonceTag) || !bytesEqual(ans[4:8], keySelector) {
		return nil, fmt.Errorf("RPC_NONCE mismatch")
	}
	rpcNonceSrv := ans[16:32]

	peer := raw.RemoteAddr().(*net.TCPAddr)
	local := raw.LocalAddr().(*net.TCPAddr)

	tgIP := reverseIPv4(peer.IP.To4())
	myIP := reverseIPv4(net.ParseIP(localIP).To4())
	if tgIP == nil || myIP == nil {
		return nil, fmt.Errorf("middle proxy требует IPv4")
	}

	tgPort := make([]byte, 2)
	binary.LittleEndian.PutUint16(tgPort, uint16(peer.Port))
	myPort := make([]byte, 2)
	binary.LittleEndian.PutUint16(myPort, uint16(local.Port))

	encKey, encIV := deriveKeys(rpcNonceSrv, nonce, cryptoTS, tgIP, myPort, []byte("CLIENT"), myIP, tgPort, secret)
	decKey, decIV := deriveKeys(rpcNonceSrv, nonce, cryptoTS, tgIP, myPort, []byte("SERVER"), myIP, tgPort, secret)

	cbc, err := newCBCConn(raw, encKey, encIV, decKey, decIV)
	if err != nil {
		return nil, err
	}

	slog.Debug("middle proxy keys",
		"srv_ip", peer.IP.String(), "srv_port", peer.Port,
		"clt_ip", localIP, "clt_port", local.Port,
	)

	clientIPU32 := ipv4ToU32(net.ParseIP(localIP))
	serverIPU32 := ipv4ToU32(peer.IP)
	handshakeMsg := buildHandshakePayload(clientIPU32, uint16(local.Port), serverIPU32, uint16(peer.Port))

	if err := writeFrame(cbc, writeSeq, handshakeMsg); err != nil {
		return nil, fmt.Errorf("RPC_HANDSHAKE: %w", err)
	}
	writeSeq++

	handshakeAns, err := readFrame(cbc, &readSeq)
	if err != nil {
		if err == io.EOF || errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("RPC_HANDSHAKE ans: EOF (проверьте middle_proxy_nat_ip=%q — должен совпадать с публичным IPv4 исходящих соединений)", localIP)
		}
		return nil, fmt.Errorf("RPC_HANDSHAKE ans: %w", err)
	}
	if len(handshakeAns) != 32 {
		return nil, fmt.Errorf("RPC_HANDSHAKE ans len=%d", len(handshakeAns))
	}
	if !bytesEqual(handshakeAns[:4], rpcHandshakeTag) {
		return nil, fmt.Errorf("RPC_HANDSHAKE type mismatch")
	}

	return &relayConn{raw: raw, cbc: cbc, readSeq: readSeq, writeSeq: writeSeq}, nil
}

// buildHandshakePayload — RPC_HANDSHAKE (32 байта): IP/порт клиента и ME-сервера.
func buildHandshakePayload(clientIP uint32, clientPort uint16, serverIP uint32, serverPort uint16) []byte {
	p := make([]byte, 32)
	copy(p[0:4], rpcHandshakeTag)
	binary.LittleEndian.PutUint32(p[8:12], clientIP)
	binary.LittleEndian.PutUint16(p[12:14], clientPort)
	binary.LittleEndian.PutUint16(p[14:16], uint16(os.Getpid()&0xffff))
	binary.LittleEndian.PutUint32(p[16:20], uint32(time.Now().Unix()))
	binary.LittleEndian.PutUint32(p[20:24], serverIP)
	binary.LittleEndian.PutUint16(p[24:26], serverPort)
	return p
}

func ipv4ToU32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}

func u32le(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func reverseIPv4(ip net.IP) []byte {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	out := make([]byte, 4)
	for i := 0; i < 4; i++ {
		out[i] = ip4[3-i]
	}
	return out
}

func localIPv4(conn *net.TCPConn) string {
	addr := conn.LocalAddr()
	if tcp, ok := addr.(*net.TCPAddr); ok {
		if ip4 := tcp.IP.To4(); ip4 != nil {
			return ip4.String()
		}
	}
	return ""
}

func localPort(conn *net.TCPConn) int {
	if tcp, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		return tcp.Port
	}
	return 0
}
