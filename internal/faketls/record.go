package faketls

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// RecordConn снимает/добавляет TLS Application Data записи поверх TCP.
type RecordConn struct {
	net.Conn
	readBuf bytes.Buffer
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

// Write оборачивает данные в TLS Application Data записи.
func (c *RecordConn) Write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > maxRecordPayload {
			chunk = chunk[:maxRecordPayload]
		}

		var rec [5]byte
		rec[0] = recordApplicationData
		rec[1] = 0x03
		rec[2] = 0x03
		binary.BigEndian.PutUint16(rec[3:5], uint16(len(chunk)))

		combined := make([]byte, 5+len(chunk))
		copy(combined, rec[:])
		copy(combined[5:], chunk)
		if _, err := c.Conn.Write(combined); err != nil {
			return total, err
		}
		total += len(chunk)
		b = b[len(chunk):]
	}
	return total, nil
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
