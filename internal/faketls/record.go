package faketls

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	drsInitialChunk = 1369
	drsRampRecords  = 8
	drsRampBytes    = 128 * 1024
)

// RecordConn снимает/добавляет TLS Application Data записи поверх TCP.
type RecordConn struct {
	net.Conn
	readBuf        bytes.Buffer
	Policy         RecordPolicy
	recordsWritten int
	bytesWritten   int64
	splitDone      bool
}

// Read читает полезную нагрузку из TLS Application Data записей.
func (c *RecordConn) Read(b []byte) (int, error) {
	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(b)
	}

	header := make([]byte, 5)
	if _, err := io.ReadFull(c.Conn, header); err != nil {
		return 0, err
	}

	recType := header[0]
	payloadLen := int(binary.BigEndian.Uint16(header[3:5]))
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(c.Conn, payload); err != nil {
		return 0, err
	}

	if recType != recordApplicationData {
		return c.Read(b)
	}

	n := copy(b, payload)
	if n < len(payload) {
		_, _ = c.readBuf.Write(payload[n:])
	}
	return n, nil
}

// Write оборачивает данные в TLS Application Data записи с динамическим размером.
func (c *RecordConn) Write(b []byte) (int, error) {
	policy := c.Policy.Normalize()
	total := 0

	// Split-TLS: первая запись — 1 байт
	if policy.EnableSplitTLS && !c.splitDone && len(b) > 0 {
		n, err := c.writeRecord(b[:1])
		if err != nil {
			return total, err
		}
		total += n
		b = b[1:]
		c.splitDone = true
	}

	for len(b) > 0 {
		chunkSize := c.outboundChunkSize(policy, len(b))
		chunk := b[:chunkSize]

		n, err := c.writeRecord(chunk)
		if err != nil {
			return total, err
		}
		total += n
		b = b[chunkSize:]
	}
	return total, nil
}

func (c *RecordConn) outboundChunkSize(policy RecordPolicy, remaining int) int {
	if remaining <= policy.MinChunk {
		return remaining
	}

	maxChunk := policy.MaxChunk
	if policy.EnableDRS {
		if c.recordsWritten < drsRampRecords && c.bytesWritten < drsRampBytes {
			if maxChunk > drsInitialChunk {
				maxChunk = drsInitialChunk
			}
		}
	}

	size := policy.chunkSizeWithMax(remaining, maxChunk)
	return size
}

func (c *RecordConn) writeRecord(chunk []byte) (int, error) {
	var rec [5]byte
	rec[0] = recordApplicationData
	rec[1] = 0x03
	rec[2] = 0x03
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(chunk)))

	combined := make([]byte, 5+len(chunk))
	copy(combined, rec[:])
	copy(combined[5:], chunk)
	if _, err := c.Conn.Write(combined); err != nil {
		return 0, err
	}
	c.recordsWritten++
	c.bytesWritten += int64(len(chunk))
	return len(chunk), nil
}

func (p RecordPolicy) chunkSizeWithMax(remaining, maxChunk int) int {
	p = p.Normalize()
	if remaining <= p.MinChunk {
		return remaining
	}
	size := p.chunkSize(remaining)
	if size > maxChunk {
		return maxChunk
	}
	return size
}

// PrefixConn возвращает уже прочитанный первый байт при чтении.
type PrefixConn struct {
	net.Conn
	Prefix []byte
}

// Read сначала отдаёт Prefix, затем читает из базового соединения.
func (c *PrefixConn) Read(b []byte) (int, error) {
	if len(c.Prefix) > 0 {
		n := copy(b, c.Prefix)
		c.Prefix = c.Prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

// IsHandshakeRecord проверяет, похоже ли соединение на TLS handshake.
func IsHandshakeRecord(first byte) bool {
	return first == recordHandshake
}

// RedirectToDomain отправляет HTTP-редирект на домен маскировки.
func RedirectToDomain(conn net.Conn, domain string) error {
	body := fmt.Sprintf("https://%s/\r\n", domain)
	response := "HTTP/1.1 302 Found\r\n" +
		"Connection: close\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Location: https://" + domain + "/\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)) +
		body
	_, err := conn.Write([]byte(response))
	return err
}
