//go:build realtelegram

package proxy_test

import (
	"context"
	"errors"
	"io"
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

	reqPQ, err := testclient.BuildReqPQMulti()
	if err != nil {
		t.Fatal(err)
	}
	if err := testclient.WritePaddedIntermediate(conn, reqPQ); err != nil {
		t.Fatal(err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	resp, err := testclient.ReadPaddedIntermediate(conn)
	if skipIfTelegramUnavailable(t, err) {
		return
	}
	if !testclient.IsResPQ(resp) {
		t.Fatalf("ожидался resPQ, получено %d байт", len(resp))
	}
	t.Logf("ответ resPQ: %d байт", len(resp))
}

// TestE2EDirectDC проверяет obfuscated2 + req_pq_multi напрямую с DC2.
func TestE2EDirectDC(t *testing.T) {
	if os.Getenv("PHANTOM_E2E_TELEGRAM") == "" {
		t.Skip("PHANTOM_E2E_TELEGRAM не задан")
	}

	conn, err := net.DialTimeout("tcp", "149.154.167.51:443", 10*time.Second)
	if skipIfTelegramUnavailable(t, err) {
		return
	}
	defer conn.Close()

	hdr, enc, dec, err := obfuscated2.ClientStreams(2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(hdr); err != nil {
		t.Fatal(err)
	}

	dc := &obfuscated2.Conn{Conn: conn, EncStream: enc, DecStream: dec}

	reqPQ, err := testclient.BuildReqPQMulti()
	if err != nil {
		t.Fatal(err)
	}
	if err := testclient.WritePaddedIntermediate(dc, reqPQ); err != nil {
		t.Fatal(err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	resp, err := testclient.ReadPaddedIntermediate(dc)
	if skipIfTelegramUnavailable(t, err) {
		return
	}
	if !testclient.IsResPQ(resp) {
		t.Fatalf("ожидался resPQ, получено %d байт", len(resp))
	}
	t.Logf("прямой ответ resPQ: %d байт", len(resp))
}

// skipIfTelegramUnavailable пропускает тест при сетевых проблемах (типично для CI).
func skipIfTelegramUnavailable(t *testing.T, err error) bool {
	t.Helper()
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.Is(err, io.EOF) || errors.As(err, &netErr) && netErr.Timeout() {
		t.Skipf("Telegram DC недоступен или отклонил соединение: %v", err)
		return true
	}
	t.Fatal(err)
	return true
}
