package obfuscated2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const connTypePaddedIntermediate uint32 = 0xdddddddd

// Conn — AES-CTR обёртка поверх TCP.
type Conn struct {
	net.Conn
	EncStream cipher.Stream
	DecStream cipher.Stream
}

func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.DecStream.XORKeyStream(b[:n], b[:n])
	}
	return n, err
}

func (c *Conn) Write(b []byte) (int, error) {
	buf := make([]byte, len(b))
	c.EncStream.XORKeyStream(buf, b)
	return c.Conn.Write(buf)
}

func (c *Conn) CloseWrite() error {
	type halfCloser interface {
		CloseWrite() error
	}
	if hc, ok := c.Conn.(halfCloser); ok {
		return hc.CloseWrite()
	}
	if tcp, ok := c.Conn.(*net.TCPConn); ok {
		return tcp.CloseWrite()
	}
	return nil
}

// Handshake выполняет входящий obfuscated2 handshake.
// secret — 16-байтовый ключ ee/dd-секрета; для Fake TLS обязателен (SHA256(header_key||secret)).
func Handshake(r io.Reader, rawConn net.Conn, secret []byte) (*Conn, int, error) {
	header := make([]byte, 64)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, 0, fmt.Errorf("чтение obfuscated2 заголовка: %w", err)
	}

	reversed := make([]byte, 64)
	for i := 0; i < 64; i++ {
		reversed[i] = header[63-i]
	}

	var decKey [32]byte
	if secret != nil {
		decKey = deriveKey(header[8:40], secret)
	} else {
		copy(decKey[:], header[8:40])
	}
	decIV := make([]byte, 16)
	copy(decIV, header[40:56])
	dec := newCTR(decKey[:], decIV)

	var encKey [32]byte
	if secret != nil {
		encKey = deriveKey(reversed[8:40], secret)
	} else {
		copy(encKey[:], reversed[8:40])
	}
	encIV := make([]byte, 16)
	copy(encIV, reversed[40:56])
	enc := newCTR(encKey[:], encIV)

	decrypted := make([]byte, 64)
	dec.XORKeyStream(decrypted, header)

	connType := binary.LittleEndian.Uint32(decrypted[56:60])
	if connType != connTypePaddedIntermediate {
		return nil, 0, fmt.Errorf("неверный тип соединения: 0x%08x", connType)
	}

	dcID := int(int16(binary.LittleEndian.Uint16(decrypted[60:62])))

	return &Conn{
		Conn:      rawConn,
		EncStream: enc,
		DecStream: dec,
	}, dcID, nil
}

// OutgoingHeader создаёт 64-байтовый заголовок для прямого соединения к DC (без секрета прокси).
func OutgoingHeader(dcID int) (header []byte, enc cipher.Stream, dec cipher.Stream, err error) {
	return outgoingHeader(dcID, nil)
}

// OutgoingHeaderWithSecret создаёт заголовок клиента после Fake TLS (ee) с deriveKey(secret).
func OutgoingHeaderWithSecret(dcID int, secret []byte) (header []byte, enc cipher.Stream, dec cipher.Stream, err error) {
	return outgoingHeader(dcID, secret)
}

func outgoingHeader(dcID int, secret []byte) (header []byte, enc cipher.Stream, dec cipher.Stream, err error) {
	header = make([]byte, 64)

	for {
		if _, err = io.ReadFull(rand.Reader, header); err != nil {
			return nil, nil, nil, err
		}
		if header[0] == 0xef || header[0] == 0x48 || header[0] == 0x50 ||
			header[0] == 0x47 || header[0] == 0x16 || header[0] == 0x14 {
			continue
		}
		if header[4] == 0 && header[5] == 0 && header[6] == 0 && header[7] == 0 {
			continue
		}
		break
	}

	binary.LittleEndian.PutUint32(header[56:60], connTypePaddedIntermediate)
	binary.LittleEndian.PutUint16(header[60:62], uint16(int16(dcID)))

	reversed := make([]byte, 64)
	for i := 0; i < 64; i++ {
		reversed[i] = header[63-i]
	}

	encIV := make([]byte, 16)
	copy(encIV, header[40:56])
	decIV := make([]byte, 16)
	copy(decIV, reversed[40:56])

	var encKey, decKey []byte
	if len(secret) > 0 {
		ek := deriveKey(header[8:40], secret)
		dk := deriveKey(reversed[8:40], secret)
		encKey = ek[:]
		decKey = dk[:]
	} else {
		encKey = make([]byte, 32)
		copy(encKey, header[8:40])
		decKey = make([]byte, 32)
		copy(decKey, reversed[8:40])
	}

	enc = newCTR(encKey, encIV)
	dec = newCTR(decKey, decIV)

	encrypted := make([]byte, 64)
	enc.XORKeyStream(encrypted, header)
	copy(header[56:64], encrypted[56:64])

	return header, enc, dec, nil
}

// OutgoingConn оборачивает исходящее соединение к DC.
type OutgoingConn struct {
	net.Conn
	EncStream cipher.Stream
	DecStream cipher.Stream
}

func (c *OutgoingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.DecStream.XORKeyStream(b[:n], b[:n])
	}
	return n, err
}

func (c *OutgoingConn) Write(b []byte) (int, error) {
	buf := make([]byte, len(b))
	c.EncStream.XORKeyStream(buf, b)
	return c.Conn.Write(buf)
}

func (c *OutgoingConn) CloseWrite() error {
	if tcp, ok := c.Conn.(*net.TCPConn); ok {
		return tcp.CloseWrite()
	}
	return nil
}

func newCTR(key, iv []byte) cipher.Stream {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return cipher.NewCTR(block, iv)
}

func deriveKey(headerKey, secret []byte) [32]byte {
	combined := make([]byte, len(headerKey)+len(secret))
	copy(combined, headerKey)
	copy(combined[len(headerKey):], secret)
	return sha256.Sum256(combined)
}
