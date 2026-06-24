package faketls

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"time"
)

// ReadRecorder записывает все прочитанные байты для последующего splice.
type ReadRecorder struct {
	net.Conn
	capture bytes.Buffer
	pending bytes.Buffer
}

// Read читает из pending или соединения, накапливая capture для splice.
func (r *ReadRecorder) Read(p []byte) (int, error) {
	if r.pending.Len() > 0 {
		n, err := r.pending.Read(p)
		return n, err
	}
	n, err := r.Conn.Read(p)
	if n > 0 {
		_, _ = r.capture.Write(p[:n])
	}
	return n, err
}

// Snapshot возвращает копию всех прочитанных байтов.
func (r *ReadRecorder) Snapshot() []byte {
	return append([]byte(nil), r.capture.Bytes()...)
}

// Prepend добавляет уже прочитанные байты (первый байт до recorder).
func (r *ReadRecorder) Prepend(b []byte) {
	if len(b) == 0 {
		return
	}
	_, _ = r.pending.Write(b)
	_, _ = r.capture.Write(b)
}

// SpliceToHost прозрачно проксирует TCP на mask host (domain fronting).
func SpliceToHost(client net.Conn, prefix []byte, host string, port int) error {
	if host == "" {
		return fmt.Errorf("host для splice пуст")
	}
	if port <= 0 {
		port = 443
	}

	target := fmt.Sprintf("%s:%d", host, port)
	upstream, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial %s: %w", target, err)
	}
	defer upstream.Close()

	if len(prefix) > 0 {
		if _, err := upstream.Write(prefix); err != nil {
			return fmt.Errorf("запись prefix: %w", err)
		}
	}

	errCh := make(chan error, 2)
	go func() { _, err := io.Copy(upstream, client); errCh <- err }()
	go func() { _, err := io.Copy(client, upstream); errCh <- err }()
	<-errCh
	return nil
}
