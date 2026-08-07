package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	relaypkg "github.com/RioTwWks/PhantomProxy/internal/relay"
)

func (s *Server) serveRelayBack(ctx context.Context) error {
	cfg := s.rt.Snapshot()
	if !cfg.Relay.IsBack() {
		return nil
	}
	psk, err := cfg.Relay.PSKBytes()
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.Relay.ListenAddr())
	if err != nil {
		return fmt.Errorf("relay listen %s: %w", cfg.Relay.ListenAddr(), err)
	}
	slog.Info("relay back слушает", "addr", cfg.Relay.ListenAddr())

	return relaypkg.ServeBack(ctx, ln, psk, func(ctx context.Context, meta relaypkg.Meta, stream net.Conn) error {
		defer stream.Close()
		return s.relayBackToDC(ctx, meta, stream, "relay")
	})
}
