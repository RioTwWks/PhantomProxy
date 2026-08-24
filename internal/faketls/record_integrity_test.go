package faketls

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
)

func TestRecordConnLargeDownloadIntegrity(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	server := &RecordConn{
		Conn: c1,
		Policy: RecordPolicy{
			MinChunk:       200,
			MaxChunk:       800,
			EnableDRS:      true,
			EnableSplitTLS: true,
			DecoyPermille:  50, // должен игнорироваться, иначе порча потока
		},
	}
	client := &RecordConn{Conn: c2, Policy: RecordPolicy{MinChunk: 512, MaxChunk: 4096}}

	const size = 256 * 1024
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := server.Write(payload)
		errCh <- err
		_ = c1.Close()
	}()

	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("corruption: got %d bytes, want %d; first mismatch at %d",
			len(got), len(payload), firstDiff(got, payload))
	}
}

func TestRecordConnDecoyDoesNotInjectAppData(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	server := &RecordConn{
		Conn:   c1,
		Policy: RecordPolicy{MinChunk: 64, MaxChunk: 128, DecoyPermille: 1000},
	}
	client := &RecordConn{Conn: c2}

	msg := []byte("obfuscated2-ciphertext-without-decoy-noise")
	go func() {
		_, _ = server.Write(msg)
		_ = c1.Close()
	}()

	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("decoy injected into stream: got %q want %q", got, msg)
	}
	if server.decoySent != 0 {
		t.Fatalf("decoySent=%d, ожидался 0", server.decoySent)
	}
}

func firstDiff(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}
