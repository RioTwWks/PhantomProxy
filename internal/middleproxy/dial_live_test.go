package middleproxy

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestDialMiddleProxyLive(t *testing.T) {
	if os.Getenv("PHANTOM_E2E_TELEGRAM") != "1" {
		t.Skip("PHANTOM_E2E_TELEGRAM не задан")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := Dial(ctx, DialOpts{
		DCID:        2,
		LocalIP:     os.Getenv("PHANTOM_ME_NAT_IP"),
		DialTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}
