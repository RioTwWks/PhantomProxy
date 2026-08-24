package relay_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/RioTwWks/PhantomProxy/internal/relay"
)

func TestRelayLargeDownloadIntegrity(t *testing.T) {
	psk := []byte("test-psk-32-bytes-long-enough!!")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const size = 512 * 1024
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = relay.ServeBack(ctx, ln, psk, func(ctx context.Context, meta relay.Meta, stream net.Conn) error {
			if meta.DCID != -2 {
				t.Errorf("dcID=%d want -2", meta.DCID)
			}
			// Имитация media download с DC: большой ответ.
			_, err := stream.Write(payload)
			return err
		})
	}()

	time.Sleep(30 * time.Millisecond)
	conn, err := relay.DialFront(ctx, ln.Addr().String(), psk, -2, "203.0.113.1:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	got := make([]byte, size)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("PHRP framing corruption на большом download")
	}
	cancel()
	wg.Wait()
}

func TestRelayParallelSessionsIntegrity(t *testing.T) {
	psk := []byte("test-psk-32-bytes-long-enough!!")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const (
		sessions = 8
		size     = 64 * 1024
	)

	go func() {
		_ = relay.ServeBack(ctx, ln, psk, func(ctx context.Context, meta relay.Meta, stream net.Conn) error {
			buf := make([]byte, size)
			if _, err := io.ReadFull(stream, buf); err != nil {
				return err
			}
			_, err := stream.Write(buf)
			return err
		})
	}()
	time.Sleep(30 * time.Millisecond)

	var wg sync.WaitGroup
	errCh := make(chan error, sessions)
	for i := 0; i < sessions; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			dc := -2
			if id%2 == 0 {
				dc = 2
			}
			conn, err := relay.DialFront(ctx, ln.Addr().String(), psk, dc, "")
			if err != nil {
				errCh <- err
				return
			}
			defer conn.Close()

			payload := bytes.Repeat([]byte{byte(id)}, size)
			if _, err := conn.Write(payload); err != nil {
				errCh <- err
				return
			}
			got := make([]byte, size)
			if _, err := io.ReadFull(conn, got); err != nil {
				errCh <- err
				return
			}
			if !bytes.Equal(got, payload) {
				errCh <- io.ErrUnexpectedEOF
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	cancel()
}
