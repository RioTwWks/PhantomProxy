package middleproxy

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/RioTwWks/PhantomProxy/internal/obfuscated2"
	"github.com/RioTwWks/PhantomProxy/internal/telegram"
)

func TestDialDirectDCLive(t *testing.T) {
	if os.Getenv("PHANTOM_E2E_TELEGRAM") != "1" {
		t.Skip("PHANTOM_E2E_TELEGRAM не задан")
	}

	addr, err := telegram.ResolveAddr(2, "")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	hdr, _, _, err := obfuscated2.OutgoingHeader(2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(hdr); err != nil {
		t.Fatal(err)
	}
}
