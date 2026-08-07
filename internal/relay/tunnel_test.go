package relay_test

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/RioTwWks/PhantomProxy/internal/relay"
)

func TestRelayRoundTrip(t *testing.T) {
	psk := []byte("test-psk-32-bytes-long-enough!!")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = relay.ServeBack(ctx, ln, psk, func(ctx context.Context, meta relay.Meta, stream net.Conn) error {
			if meta.DCID != 2 {
				t.Errorf("dcID = %d", meta.DCID)
			}
			if meta.ClientIP != "127.0.0.1" || meta.ClientPort != 12345 {
				t.Errorf("client = %s:%d", meta.ClientIP, meta.ClientPort)
			}
			buf := make([]byte, 64)
			n, err := stream.Read(buf)
			if err != nil {
				return err
			}
			_, err = stream.Write(buf[:n])
			return err
		})
	}()

	time.Sleep(50 * time.Millisecond)
	conn, err := relay.DialFront(ctx, ln.Addr().String(), psk, 2, "127.0.0.1:12345")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	msg := []byte("ping-relay")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if string(resp) != string(msg) {
		t.Fatalf("resp = %q", resp)
	}
	cancel()
	wg.Wait()
}
