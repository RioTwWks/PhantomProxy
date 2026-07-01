//go:build integration

package proxy_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/RioTwWks/PhantomProxy/internal/config"
	"github.com/RioTwWks/PhantomProxy/internal/faketls"
	"github.com/RioTwWks/PhantomProxy/internal/mtproto"
	"github.com/RioTwWks/PhantomProxy/internal/proxy"
	"github.com/RioTwWks/PhantomProxy/internal/runtime"
	"github.com/RioTwWks/PhantomProxy/internal/stats"
	"github.com/RioTwWks/PhantomProxy/internal/testclient"
	"github.com/RioTwWks/PhantomProxy/internal/testdc"
	"github.com/RioTwWks/PhantomProxy/internal/user"
)

const (
	secretAlice = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
	secretBob   = "ee0123456789abcdef0123456789abcdef6578616d706c652e636f6d"
)

func startTestProxy(t *testing.T, cfg config.Config) (addr string, cancel context.CancelFunc) {
	t.Helper()

	mock, err := testdc.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mock.Close() })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpAddr := ln.Addr().(*net.TCPAddr)
	_ = ln.Close()

	cfg.Listen.Host = "127.0.0.1"
	cfg.Listen.Port = tcpAddr.Port
	cfg.MTProto.Backend = mock.Addr()

	users := make([]user.User, 0, len(cfg.MTProto.Users))
	for _, item := range cfg.MTProto.Users {
		secret, err := mtproto.ParseSecret(item.Secret)
		if err != nil {
			t.Fatal(err)
		}
		users = append(users, user.User{Name: item.Name, Secret: secret, Enabled: true})
	}
	mgr, err := user.NewManager(users, cfg.TLS.AllowedJA3, cfg.TLS.AllowedJA4)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	rt := runtime.New("", cfg, mgr, stats.New())
	srv := proxy.New(rt, nil)
	go func() { _ = srv.Serve(ctx) }()
	waitForTCP(t, cfg.Addr())
	return cfg.Addr(), cancel
}

func TestIntegrationMultiUserProxy(t *testing.T) {
	cfg := baseConfig()
	addr, cancel := startTestProxy(t, cfg)
	defer cancel()

	t.Run("alice", func(t *testing.T) {
		secret, _ := mtproto.ParseSecret(secretAlice)
		conn := dialClient(t, secret, addr, cfg.RecordPolicy())
		defer conn.Close()
		assertRoundTrip(t, conn, []byte("mtproto-alice"))
	})

	t.Run("bob", func(t *testing.T) {
		secret, _ := mtproto.ParseSecret(secretBob)
		conn := dialClient(t, secret, addr, cfg.RecordPolicy())
		defer conn.Close()
		assertRoundTrip(t, conn, []byte("mtproto-bob"))
	})

	t.Run("wrong_secret", func(t *testing.T) {
		wrong, err := mtproto.ParseSecret("eeffffffffffffffffffffffffffffffff6578616d706c652e636f6d")
		if err != nil {
			t.Fatal(err)
		}
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := faketls.WriteClientHello(conn, wrong); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 32)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			t.Fatal("ожидался HTTP redirect при неверном секрете")
		}
		if string(buf[:n])[:4] != "HTTP" {
			t.Fatalf("ответ = %q", buf[:n])
		}
	})
}

func TestIntegrationDynamicRecordSizes(t *testing.T) {
	cfg := baseConfig()
	cfg.TLS.RecordMinChunk = 128
	cfg.TLS.RecordMaxChunk = 256

	addr, cancel := startTestProxy(t, cfg)
	defer cancel()

	secret, _ := mtproto.ParseSecret(secretAlice)
	policy := faketls.RecordPolicy{MinChunk: 100, MaxChunk: 200}
	conn := dialClient(t, secret, addr, policy)
	defer conn.Close()

	large := make([]byte, 1024)
	for i := range large {
		large[i] = byte(i % 251)
	}
	assertRoundTrip(t, conn, large)
}

func TestIntegrationJA3Fingerprint(t *testing.T) {
	secret, err := mtproto.ParseSecret(secretAlice)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := faketls.BuildClientHello(secret)
	if err != nil {
		t.Fatal(err)
	}
	ja3 := faketls.JA3(ch.Raw)
	ja4 := faketls.JA4(ch.Raw)
	if len(ja3) != 32 {
		t.Fatalf("JA3 len = %d", len(ja3))
	}
	if ja4 == "" {
		t.Fatal("JA4 пуст")
	}
	t.Logf("Chrome-like fingerprint JA3=%s JA4=%s", ja3, ja4)
}

func baseConfig() config.Config {
	return config.Config{
		MTProto: config.MTProtoConfig{
			Users: []config.UserConfig{
				{Name: "alice", Secret: secretAlice},
				{Name: "bob", Secret: secretBob},
			},
		},
		Protocols: config.ProtocolsConfig{FakeTLS: true, Secure: true},
		Fronting:  config.FrontingConfig{Action: "redirect"},
		TLS: config.TLSConfig{
			RecordMinChunk: 256,
			RecordMaxChunk: 1024,
			NoiseMean:      2500,
			NoiseJitter:    400,
		},
		Fallback: config.FallbackConfig{Upstream: "http://127.0.0.1:1"},
	}
}

func dialClient(t *testing.T, secret mtproto.Secret, addr string, policy faketls.RecordPolicy) net.Conn {
	t.Helper()
	client := &testclient.Client{Secret: secret, Policy: policy}
	conn, err := client.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func assertRoundTrip(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	resp, err := testclient.RoundTrip(conn, payload, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) != len(payload) {
		t.Fatalf("len = %d, want %d", len(resp), len(payload))
	}
	for i := range payload {
		if resp[i] != payload[i] {
			t.Fatalf("byte %d = %d, want %d", i, resp[i], payload[i])
		}
	}
}
