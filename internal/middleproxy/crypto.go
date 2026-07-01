package middleproxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const cbcBlockSize = 16

// deriveKeys вычисляет AES-CBC ключи для middle proxy handshake.
func deriveKeys(nonceSrv, nonceClt, cltTS, srvIP, cltPort, purpose, cltIP, srvPort, secret []byte) (key, iv []byte) {
	emptyIP := []byte{0, 0, 0, 0}
	if len(cltIP) == 0 {
		cltIP = emptyIP
	}
	if len(srvIP) == 0 {
		srvIP = emptyIP
	}

	s := make([]byte, 0, 128)
	s = append(s, nonceSrv...)
	s = append(s, nonceClt...)
	s = append(s, cltTS...)
	s = append(s, srvIP...)
	s = append(s, cltPort...)
	s = append(s, purpose...)
	s = append(s, cltIP...)
	s = append(s, srvPort...)
	s = append(s, secret...)
	s = append(s, nonceSrv...)
	s = append(s, nonceClt...)

	md5sum := md5.Sum(s[1:])
	sha1sum := sha1.Sum(s)

	key = make([]byte, 32)
	copy(key[:12], md5sum[:12])
	copy(key[12:], sha1sum[:20])

	ivHash := md5.Sum(s[2:])
	return key, ivHash[:]
}

type cbcConn struct {
	net.Conn
	enc cipher.BlockMode
	dec cipher.BlockMode
	buf []byte
}

func newCBCConn(conn net.Conn, encKey, encIV, decKey, decIV []byte) (*cbcConn, error) {
	encBlock, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	decBlock, err := aes.NewCipher(decKey)
	if err != nil {
		return nil, err
	}
	return &cbcConn{
		Conn: conn,
		enc:  cipher.NewCBCEncrypter(encBlock, encIV),
		dec:  cipher.NewCBCDecrypter(decBlock, decIV),
	}, nil
}

func (c *cbcConn) Write(p []byte) (int, error) {
	pad := cbcBlockSize - (len(p) % cbcBlockSize)
	if pad == 0 {
		pad = cbcBlockSize
	}
	buf := make([]byte, len(p)+pad)
	copy(buf, p)
	for i := len(p); i < len(buf); i++ {
		buf[i] = byte(pad)
	}
	c.enc.CryptBlocks(buf, buf)
	_, err := c.Conn.Write(buf)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *cbcConn) Read(p []byte) (int, error) {
	for len(c.buf) == 0 {
		block := make([]byte, cbcBlockSize)
		if _, err := readFull(c.Conn, block); err != nil {
			return 0, err
		}
		c.dec.CryptBlocks(block, block)
		pad := int(block[len(block)-1])
		if pad <= 0 || pad > cbcBlockSize {
			return 0, fmt.Errorf("неверный CBC padding")
		}
		c.buf = append(c.buf[:0], block[:len(block)-pad]...)
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *cbcConn) Close() error {
	return c.Conn.Close()
}

func readFull(r io.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := r.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func writeFrame(w io.Writer, seqNo int32, msg []byte) error {
	lenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBytes, uint32(len(msg)+12))

	seqBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(seqBytes, uint32(seqNo))

	body := append(append(lenBytes, seqBytes...), msg...)
	crc := crc32IEEE(body)
	checksum := make([]byte, 4)
	binary.LittleEndian.PutUint32(checksum, crc)

	full := append(body, checksum...)
	padding := framePadding(len(full))
	_, err := w.Write(append(full, padding...))
	return err
}

func readFrame(r io.Reader, seqNo *int32) ([]byte, error) {
	lenBytes := make([]byte, 4)
	if _, err := readFull(r, lenBytes); err != nil {
		return nil, err
	}
	msgLen := int32(binary.LittleEndian.Uint32(lenBytes))

	seqBytes := make([]byte, 4)
	if _, err := readFull(r, seqBytes); err != nil {
		return nil, err
	}
	gotSeq := int32(binary.LittleEndian.Uint32(seqBytes))
	if *seqNo != gotSeq {
		return nil, fmt.Errorf("unexpected seq_no: got %d want %d", gotSeq, *seqNo)
	}
	*seqNo++

	dataLen := int(msgLen) - 12
	if dataLen < 0 {
		return nil, fmt.Errorf("bad frame len %d", msgLen)
	}
	data := make([]byte, dataLen)
	if _, err := readFull(r, data); err != nil {
		return nil, err
	}

	checksum := make([]byte, 4)
	if _, err := readFull(r, checksum); err != nil {
		return nil, err
	}

	// padding до кратности 16
	used := 4 + 4 + dataLen + 4
	padLen := cbcBlockSize - (used % cbcBlockSize)
	if padLen < cbcBlockSize {
		skip := make([]byte, padLen)
		if _, err := readFull(r, skip); err != nil {
			return nil, err
		}
	}

	return data, nil
}

func framePadding(n int) []byte {
	const filler = "\x04\x00\x00\x00"
	if n%cbcBlockSize == 0 {
		return nil
	}
	pad := cbcBlockSize - (n % cbcBlockSize)
	out := make([]byte, pad)
	for i := 0; i < pad; i += 4 {
		copy(out[i:], filler)
	}
	return out
}

func crc32IEEE(data []byte) uint32 {
	var crc uint32 = 0xffffffff
	for _, b := range data {
		crc ^= uint32(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xedb88320
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}
