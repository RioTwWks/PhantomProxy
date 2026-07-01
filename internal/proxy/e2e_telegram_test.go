//go:build realtelegram

package proxy_test

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/RioTwWks/PhantomProxy/internal/config"
	"github.com/RioTwWks/PhantomProxy/internal/mtproto"
	"github.com/RioTwWks/PhantomProxy/internal/obfuscated2"
	"github.com/RioTwWks/PhantomProxy/internal/proxy"
	"github.com/RioTwWks/PhantomProxy/internal/runtime"
	"github.com/RioTwWks/PhantomProxy/internal/stats"
	"github.com/RioTwWks/PhantomProxy/internal/testclient"
	"github.com/RioTwWks/PhantomProxy/internal/user"
)

const e2eSecret = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"

// TestE2ERealTelegram проверяет полный путь клиент → прокси → реальный DC Telegram.
// Запуск: PHANTOM_E2E_TELEGRAM=1 go test -tags=realtelegram -timeout=2m ./internal/proxy/...
func TestE2ERealTelegram(t *testing.T) {
	if os.Getenv("PHANTOM_E2E_TELEGRAM") == "" {
		t.Skip("PHANTOM_E2E_TELEGRAM не задан")
	}

	secret, err := mtproto.ParseSecret(e2eSecret)
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := user.NewManager([]user.User{{Name: "e2e", Secret: secret, Enabled: true}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cfg := config.Config{
		Listen:    config.ListenConfig{Host: "127.0.0.1", Port: port},
		MTProto:   config.MTProtoConfig{Backend: ""},
		Protocols: config.ProtocolsConfig{FakeTLS: true, Secure: true},
		Fronting:  config.FrontingConfig{Action: "redirect"},
		TLS:       config.TLSConfig{RecordMinChunk: 512, RecordMaxChunk: 4096, NoiseMean: 3000, NoiseJitter: 800},
		Fallback:  config.FallbackConfig{Upstream: "http://127.0.0.1:1"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rt := runtime.New("", cfg, mgr, stats.New())
	srv := proxy.New(rt, nil)
	go func() { _ = srv.Serve(ctx) }()
	waitForTCP(t, cfg.Addr())

	client := &testclient.Client{Secret: secret}
	conn, err := client.Dial(cfg.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// MTProto req_pq_multi — минимальный запрос после handshake
	reqPQ := []byte{
		0, 0, 0, 0, 0, 0, 0, 0,
		0x20, 0, 0, 0,
		0xbe, 0x7e, 0x67, 0x72,
		0, 0, 0, 0,
	}
	if _, err := conn.Write(reqPQ); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("нет ответа от Telegram DC: %v", err)
	}
	if n < 8 {
		t.Fatalf("короткий ответ: %d байт", n)
	}
	t.Logf("ответ от DC: %d байт", n)
}

// TestE2EDirectDC проверяет obfuscated2 handshake напрямую с DC2.
func TestE2EDirectDC(t *testing.T) {
	if os.Getenv("PHANTOM_E2E_TELEGRAM") == "" {
		t.Skip("PHANTOM_E2E_TELEGRAM не задан")
	}

	conn, err := net.DialTimeout("tcp", "149.154.167.51:443", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	hdr, enc, dec, err := obfuscated2.OutgoingHeader(2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(hdr); err != nil {
		t.Fatal(err)
	}

	dc := &obfuscated2.OutgoingConn{Conn: conn, EncStream: enc, DecStream: dec}
	reqPQ := []byte{
		0, 0, 0, 0, 0, 0, 0, 0,
		0x20, 0, 0, 0,
		0xbe, 0x7e, 0x67, 0x72,
		0, 0, 0, 0,
	}
	if _, err := dc.Write(reqPQ); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 4096)
	n, err := dc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n < 8 {
		t.Fatalf("короткий ответ: %d", n)
	}
}
