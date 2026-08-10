package middleproxy

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/RioTwWks/PhantomProxy/internal/testclient"
)

func TestMiddleProxyReqPQLive(t *testing.T) {
	if os.Getenv("PHANTOM_E2E_TELEGRAM") != "1" {
		t.Skip("PHANTOM_E2E_TELEGRAM не задан")
	}

	adTag, _ := ParseAdTag(os.Getenv("PHANTOM_ME_AD_TAG"))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := Dial(ctx, DialOpts{
		DCID:        2,
		ClientIP:    "1.2.3.4",
		ClientPort:  12345,
		LocalIP:     os.Getenv("PHANTOM_ME_NAT_IP"),
		AdTag:       adTag,
		DialTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	reqPQ, err := testclient.BuildReqPQMulti()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := testclient.WritePaddedIntermediate(&buf, reqPQ); err != nil {
		t.Fatal(err)
	}

	if _, err := conn.Write(buf.Bytes()); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	frame, err := testclient.ReadPaddedIntermediate(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !testclient.IsResPQ(frame) {
		t.Fatalf("not resPQ, len=%d first=%x", len(frame), frame[:min(24, len(frame))])
	}
}
