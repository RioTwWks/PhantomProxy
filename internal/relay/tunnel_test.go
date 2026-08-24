package relay_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/RioTwWks/PhantomProxy/internal/relay"
	"github.com/RioTwWks/PhantomProxy/internal/telegram"
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

func TestRelayMediaDcIDSigned(t *testing.T) {
	// Front передаёт dcID=-2 (MEDIA DC2); back должен получить -2, не 65534.
	psk := []byte("test-psk-32-bytes-long-enough!!")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := make(chan int, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = relay.ServeBack(ctx, ln, psk, func(ctx context.Context, meta relay.Meta, stream net.Conn) error {
			got <- meta.DCID
			_, _ = io.Copy(io.Discard, stream)
			return nil
		})
	}()

	time.Sleep(50 * time.Millisecond)
	conn, err := relay.DialFront(ctx, ln.Addr().String(), psk, -2, "10.0.0.1:5555")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	select {
	case dc := <-got:
		if dc != -2 {
			t.Fatalf("dcID=%d want -2 (не 65534)", dc)
		}
		if dc == 65534 {
			t.Fatal("dcID прочитан как uint16")
		}
		addr, err := telegram.ResolveAddr(dc, "")
		if err != nil {
			t.Fatalf("ResolveAddr(-2): %v", err)
		}
		if addr == "" {
			t.Fatal("пустой media DC2")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for media handshake")
	}
	cancel()
	wg.Wait()
}

func TestRelayDcIDSignedBoundary(t *testing.T) {
	cases := []struct {
		name string
		dcID int
		want int
	}{
		{"main2", 2, 2},
		{"media2", -2, -2},
		{"media1", -1, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			psk := []byte("test-psk-32-bytes-long-enough!!")
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			got := make(chan int, 1)
			go func() {
				_ = relay.ServeBack(ctx, ln, psk, func(ctx context.Context, meta relay.Meta, stream net.Conn) error {
					got <- meta.DCID
					return nil
				})
			}()

			time.Sleep(30 * time.Millisecond)
			conn, err := relay.DialFront(ctx, ln.Addr().String(), psk, tc.dcID, "")
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()

			select {
			case dc := <-got:
				if dc != tc.want {
					t.Fatalf("dcID=%d want %d", dc, tc.want)
				}
				// Wire: int16(dc) как uint16 не должен попадать в логику как валидный id.
				u := uint16(int16(tc.dcID))
				if tc.dcID < 0 && int(u) == dc {
					t.Fatalf("получили unsigned wire value %d вместо signed %d", u, tc.want)
				}
			case <-time.After(time.Second):
				t.Fatal("timeout")
			}
			cancel()
		})
	}
}

func TestPHRPDcIDWireEncoding(t *testing.T) {
	// int16(-2) на проводе = 0xFFFE; парсинг должен дать -2.
	v := int16(-2)
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], uint16(v))
	if binary.BigEndian.Uint16(buf[:]) != 65534 {
		t.Fatalf("wire uint16=%d want 65534", binary.BigEndian.Uint16(buf[:]))
	}
	parsed := int(int16(binary.BigEndian.Uint16(buf[:])))
	if parsed != -2 {
		t.Fatalf("parsed=%d want -2", parsed)
	}
	if _, err := telegram.ResolveAddr(parsed, ""); err != nil {
		t.Fatalf("ResolveAddr(-2): %v", err)
	}
	if _, err := telegram.ResolveAddr(65534, ""); err == nil {
		t.Fatal("65534 не должен резолвиться")
	}
}
