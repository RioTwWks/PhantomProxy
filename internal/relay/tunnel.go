package relay

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"
)

const (
	magic            = "PHRP"
	handshakeBaseLen = 4 + 16 + 32 + 2 // magic + nonce + tag + dcID
	handshakeLen     = handshakeBaseLen + 4 + 2 // + client IPv4 + port
	maxFrameLen      = 64 * 1024
)

var (
	errBadMagic  = errors.New("relay: неверный magic")
	errBadAuth   = errors.New("relay: неверная аутентификация")
	errFrameSize = errors.New("relay: слишком большой фрейм")
)

// Meta — метаданные PHRP handshake (dcID и адрес клиента Telegram на Front).
type Meta struct {
	DCID       int
	ClientIP   string
	ClientPort int
}

// DialFront открывает зашифрованный туннель Front→Back и передаёт dcID и адрес клиента.
func DialFront(ctx context.Context, peerAddr string, psk []byte, dcID int, clientAddr string) (net.Conn, error) {
	if len(psk) == 0 {
		return nil, errors.New("relay: psk обязателен")
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", peerAddr)
	if err != nil {
		return nil, fmt.Errorf("relay dial: %w", err)
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		_ = conn.Close()
		return nil, err
	}

	mac := hmac.New(sha256.New, psk)
	mac.Write(nonce)
	tag := mac.Sum(nil)

	handshake := make([]byte, 0, handshakeLen)
	handshake = append(handshake, magic...)
	handshake = append(handshake, nonce...)
	handshake = append(handshake, tag...)
	var dcBuf [2]byte
	binary.BigEndian.PutUint16(dcBuf[:], uint16(dcID))
	handshake = append(handshake, dcBuf[:]...)

	clientIP, clientPort := parseClientAddr(clientAddr)
	if ip4 := net.ParseIP(clientIP).To4(); ip4 != nil {
		handshake = append(handshake, ip4...)
	} else {
		handshake = append(handshake, 0, 0, 0, 0)
	}
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(clientPort))
	handshake = append(handshake, portBuf[:]...)

	if _, err := conn.Write(handshake); err != nil {
		_ = conn.Close()
		return nil, err
	}

	aead, err := newAEAD(psk, nonce)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &frameConn{Conn: conn, aead: aead}, nil
}

// ServeBack принимает relay-соединения на listener и вызывает handler с meta и потоком.
func ServeBack(ctx context.Context, ln net.Listener, psk []byte, handler func(ctx context.Context, meta Meta, stream net.Conn) error) error {
	if len(psk) == 0 {
		return errors.New("relay: psk обязателен")
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				continue
			}
		}
		go func(c net.Conn) {
			defer c.Close()
			remote := c.RemoteAddr().String()
			slog.Info("relay back: входящее соединение", "remote", remote)
			dcID, framed, meta, err := acceptBack(c, psk)
			if err != nil {
				slog.Warn("relay back: handshake отклонён", "remote", remote, "err", err)
				return
			}
			meta.DCID = dcID
			slog.Info("relay back: handshake ok", "remote", remote, "dc", dcID, "client", meta.ClientIP, "client_port", meta.ClientPort)
			if err := handler(ctx, meta, framed); err != nil {
				slog.Warn("relay back: сессия завершена с ошибкой", "remote", remote, "dc", dcID, "err", err)
			}
		}(conn)
	}
}

func acceptBack(conn net.Conn, psk []byte) (int, net.Conn, Meta, error) {
	hdr := make([]byte, handshakeBaseLen)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return 0, nil, Meta{}, err
	}
	if string(hdr[:4]) != magic {
		return 0, nil, Meta{}, errBadMagic
	}
	nonce := hdr[4:20]
	tag := hdr[20:52]
	mac := hmac.New(sha256.New, psk)
	mac.Write(nonce)
	expected := mac.Sum(nil)
	if !hmac.Equal(tag, expected) {
		return 0, nil, Meta{}, errBadAuth
	}
	dcID := int(binary.BigEndian.Uint16(hdr[52:54]))

	meta := Meta{}
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	extra := make([]byte, handshakeLen-handshakeBaseLen)
	if n, err := io.ReadFull(conn, extra); err == nil && n == len(extra) {
		meta.ClientIP = net.IP(extra[:4]).String()
		meta.ClientPort = int(binary.BigEndian.Uint16(extra[4:6]))
	}
	_ = conn.SetReadDeadline(time.Time{})

	aead, err := newAEAD(psk, nonce)
	if err != nil {
		return 0, nil, Meta{}, err
	}
	return dcID, &frameConn{Conn: conn, aead: aead}, meta, nil
}

func parseClientAddr(remote string) (ip string, port int) {
	if remote == "" {
		return "", 0
	}
	host, portStr, err := net.SplitHostPort(remote)
	if err != nil {
		return remote, 0
	}
	var p int
	for _, c := range portStr {
		if c < '0' || c > '9' {
			break
		}
		p = p*10 + int(c-'0')
	}
	return host, p
}

type frameConn struct {
	net.Conn
	aead cipher.AEAD
	rbuf []byte
}

func newAEAD(psk, nonce []byte) (cipher.AEAD, error) {
	key := deriveKey(psk, nonce)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func deriveKey(psk, nonce []byte) []byte {
	h := hmac.New(sha256.New, psk)
	h.Write([]byte("phantom-relay-v1"))
	h.Write(nonce)
	return h.Sum(nil)
}

func (c *frameConn) Read(b []byte) (int, error) {
	for len(c.rbuf) == 0 {
		var hdr [4]byte
		if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
			return 0, err
		}
		n := int(binary.BigEndian.Uint32(hdr[:]))
		if n <= 0 || n > maxFrameLen {
			return 0, errFrameSize
		}
		frame := make([]byte, n)
		if _, err := io.ReadFull(c.Conn, frame); err != nil {
			return 0, err
		}
		plain, err := c.aead.Open(nil, frame[:12], frame[12:], nil)
		if err != nil {
			return 0, err
		}
		c.rbuf = plain
	}
	n := copy(b, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *frameConn) Write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > maxFrameLen-32 {
			chunk = b[:maxFrameLen-32]
		}
		if err := c.writeFrame(chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		b = b[len(chunk):]
	}
	return total, nil
}

func (c *frameConn) writeFrame(payload []byte) error {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := c.aead.Seal(nonce, nonce, payload, nil)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(sealed)))
	if _, err := c.Conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err := c.Conn.Write(sealed)
	return err
}
