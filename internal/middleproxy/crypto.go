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
	if len(p)%cbcBlockSize != 0 {
		return 0, fmt.Errorf("cbc: plaintext %d не кратен %d", len(p), cbcBlockSize)
	}
	out := make([]byte, len(p))
	c.enc.CryptBlocks(out, p)
	if _, err := c.Conn.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

func alignedCipherReadSize(need int) int {
	if need <= 0 {
		return cbcBlockSize
	}
	if r := need % cbcBlockSize; r != 0 {
		return need + (cbcBlockSize - r)
	}
	return need
}

func (c *cbcConn) ensurePlain(n int) error {
	for len(c.buf) < n {
		need := n - len(c.buf)
		cipherLen := alignedCipherReadSize(need)
		ciphertext := make([]byte, cipherLen)
		if _, err := readFull(c.Conn, ciphertext); err != nil {
			return err
		}
		plaintext := make([]byte, cipherLen)
		c.dec.CryptBlocks(plaintext, ciphertext)
		c.buf = append(c.buf, plaintext...)
	}
	return nil
}

func (c *cbcConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := c.ensurePlain(len(p)); err != nil {
		return 0, err
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
	for {
		lenBytes := make([]byte, 4)
		if _, err := readFull(r, lenBytes); err != nil {
			return nil, err
		}
		msgLen := int32(binary.LittleEndian.Uint32(lenBytes))
		if msgLen == 4 {
			continue
		}

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

		// Padding после checksum только при отправке (writeFrame), ответ ME — ровно msgLen байт.
		return data, nil
	}
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
