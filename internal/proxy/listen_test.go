package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/RioTwWks/PhantomProxy/internal/config"
	"github.com/RioTwWks/PhantomProxy/internal/mtproto"
	"github.com/RioTwWks/PhantomProxy/internal/runtime"
	"github.com/RioTwWks/PhantomProxy/internal/stats"
	"github.com/RioTwWks/PhantomProxy/internal/user"
)

func TestRebindListenIfNeeded(t *testing.T) {
	secret, err := mtproto.ParseSecret("ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d")
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := user.NewManager([]user.User{{Name: "alice", Secret: secret, Enabled: true}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	portA := freePort(t)
	portB := freePort(t)

	cfg := config.Config{
		Listen: config.ListenConfig{Host: "127.0.0.1", Port: portA},
	}
	rt := runtime.New("", cfg, mgr, stats.New())
	srv := New(rt, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	waitTCP(t, cfg.Addr())

	changed, err := srv.RebindListenIfNeeded()
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("не должно меняться при том же адресе")
	}

	cfg.Listen.Port = portB
	rt.UpdateConfig(cfg)

	changed, err = srv.RebindListenIfNeeded()
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("ожидался rebind")
	}

	waitTCP(t, cfg.Addr())
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func waitTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("сервер %s не поднялся", addr)
}
