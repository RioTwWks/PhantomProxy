package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/RioTwWks/PhantomProxy/internal/faketls"
	"github.com/RioTwWks/PhantomProxy/internal/fallback"
	"github.com/RioTwWks/PhantomProxy/internal/metrics"
	"github.com/RioTwWks/PhantomProxy/internal/obfuscated2"
	"github.com/RioTwWks/PhantomProxy/internal/runtime"
	"github.com/RioTwWks/PhantomProxy/internal/telegram"
	"github.com/RioTwWks/PhantomProxy/internal/upstream"
)

// Server принимает TCP-соединения и маршрутизирует их.
type Server struct {
	rt      *runtime.Runtime
	ln      net.Listener
	wg      sync.WaitGroup
	metrics *metrics.Server
}

// New создаёт прокси-сервер.
func New(rt *runtime.Runtime, ms *metrics.Server) *Server {
	return &Server{rt: rt, metrics: ms}
}

// Serve запускает прослушивание до отмены контекста.
func (s *Server) Serve(ctx context.Context) error {
	addr := s.rt.Snapshot().Addr()
	var err error
	s.ln, err = net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	slog.Info("прокси слушает", "addr", addr, "users", len(s.rt.Users.Users()))

	go func() {
		<-ctx.Done()
		_ = s.ln.Close()
	}()

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				s.wg.Wait()
				return nil
			default:
				slog.Error("ошибка accept", "err", err)
				continue
			}
		}

		cfg := s.rt.Snapshot()
		if cfg.Listen.ProxyProtocol {
			conn, err = acceptWithProxyProtocol(conn, true)
			if err != nil {
				slog.Debug("PROXY protocol", "err", err)
				_ = conn.Close()
				continue
			}
		}

		if s.rt.Limiter != nil && !s.rt.Limiter.Acquire(conn) {
			slog.Debug("лимит per-IP", "remote", remoteAddr(conn))
			_ = conn.Close()
			continue
		}

		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			if s.rt.Limiter != nil {
				defer s.rt.Limiter.Release(c)
			}
			s.handleConnection(ctx, c)
		}(conn)
	}
}

// Shutdown дожидается завершения активных соединений.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.ln != nil {
		_ = s.ln.Close()
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	cfg := s.rt.Snapshot()
	remote := remoteAddr(conn)

	if err := conn.SetReadDeadline(time.Now().Add(cfg.HandshakeTimeout())); err != nil {
		return
	}

	first := make([]byte, 1)
	if _, err := conn.Read(first); err != nil {
		return
	}

	if cfg.Protocols.FakeTLS && faketls.IsHandshakeRecord(first[0]) {
		rec := &faketls.ReadRecorder{Conn: conn}
		rec.Prepend(first)
		s.handleFakeTLSPath(ctx, rec, remote)
		return
	}

	if cfg.Protocols.Secure {
		header := make([]byte, 64)
		header[0] = first[0]
		if _, err := io.ReadFull(conn, header[1:]); err == nil {
			if err := s.handleSecure(ctx, conn, header, remote); err == nil {
				return
			}
		}
	}

	slog.Debug("постороннее соединение", "remote", remote, "byte", fmt.Sprintf("0x%02x", first[0]))
	_ = fallback.Serve(&faketls.PrefixConn{Conn: conn, Prefix: first}, cfg.Fallback.Upstream)
}

func (s *Server) handleFakeTLSPath(ctx context.Context, rec *faketls.ReadRecorder, remote string) {
	var ch *faketls.ClientHello

	err := func() error {
		var parseErr error
		ch, parseErr = faketls.ParseClientHello(rec)
		if parseErr != nil {
			return parseErr
		}

		if s.rt.Replay != nil && s.rt.Replay.Check(ch) {
			if s.metrics != nil {
				s.metrics.ReplayAttacks().Inc()
			}
			return fmt.Errorf("replay attack")
		}

		matched, matchErr := s.rt.Users.MatchClientHello(ch)
		if matchErr != nil {
			return matchErr
		}

		cfg := s.rt.Snapshot()
		if err := faketls.WriteServerHelloWithNoise(rec, ch, matched.Secret.Key[:], cfg.NoiseParams()); err != nil {
			return fmt.Errorf("server hello: %w", err)
		}

		tlsConn := &faketls.RecordConn{Conn: rec, Policy: cfg.RecordPolicy()}
		obfConn, dcID, err := obfuscated2.Handshake(tlsConn, tlsConn, nil)
		if err != nil {
			return fmt.Errorf("obfuscated2: %w", err)
		}

		return s.relayMTProto(ctx, rec, obfConn, dcID, matched.Name, ch, remote)
	}()

	if err != nil {
		slog.Debug("fake TLS отклонён", "remote", remote, "err", err)
		s.handleRejectedTLS(rec, ch, remote)
	}
}

func (s *Server) handleRejectedTLS(conn *faketls.ReadRecorder, ch *faketls.ClientHello, remote string) {
	cfg := s.rt.Snapshot()
	host := s.rt.Users.MaskHost()
	if ch != nil {
		if sni := ch.SNI(); sni != "" {
			host = sni
		}
	}

	prefix := conn.Snapshot()

	switch cfg.FrontingAction() {
	case "splice":
		if s.metrics != nil {
			s.metrics.FrontingConns().Inc()
		}
		if err := faketls.SpliceToHost(conn, prefix, host, cfg.FrontingPort()); err != nil {
			slog.Debug("splice", "remote", remote, "host", host, "err", err)
		}
	case "fallback":
		_ = fallback.Serve(conn, cfg.Fallback.Upstream)
	default:
		_ = faketls.RedirectToDomain(conn, host)
	}
}

func (s *Server) handleSecure(ctx context.Context, conn net.Conn, header []byte, remote string) error {
	matched, dcID, err := s.rt.Users.MatchSecureHeader(header)
	if err != nil {
		return err
	}
	obfConn, _, err := obfuscated2.ConnFromHeader(conn, header, matched.Secret.Key[:])
	if err != nil {
		return err
	}
	return s.relayMTProto(ctx, conn, obfConn, dcID, matched.Name, nil, remote)
}

func (s *Server) relayMTProto(ctx context.Context, conn net.Conn, obfConn *obfuscated2.Conn, dcID int, userName string, ch *faketls.ClientHello, remote string) error {
	_ = conn.SetReadDeadline(time.Time{})

	cfg := s.rt.Snapshot()
	dcAddr, err := telegram.ResolveAddr(dcID, cfg.MTProto.Backend)
	if err != nil {
		return err
	}

	dialer := &upstream.Dialer{
		SOCKS5:   cfg.Upstream.SOCKS5,
		PreferIP: cfg.Upstream.PreferIP,
		Timeout:  10 * time.Second,
	}
	dcConn, err := dialer.DialContext(ctx, "tcp", dcAddr)
	if err != nil {
		return fmt.Errorf("DC %s: %w", dcAddr, err)
	}
	defer dcConn.Close()

	hdr, enc, dec, err := obfuscated2.OutgoingHeader(dcID)
	if err != nil {
		return err
	}
	if _, err := dcConn.Write(hdr); err != nil {
		return err
	}

	serverConn := &obfuscated2.OutgoingConn{Conn: dcConn, EncStream: enc, DecStream: dec}

	s.rt.Stats.OnConnect(userName)
	defer s.rt.Stats.OnDisconnect(userName)

	fields := []any{"user", userName, "remote", remote, "dc", dcID, "backend", dcAddr}
	if ch != nil {
		fields = append(fields, "ja3", faketls.JA3(ch.Raw), "mode", "ee")
	} else {
		fields = append(fields, "mode", "dd")
	}
	slog.Info("клиент подключён", fields...)

	up, down := relay(obfConn, serverConn)
	s.rt.Stats.AddTraffic(userName, up, down)
	if s.metrics != nil {
		s.metrics.RecordTraffic(up, down)
	}
	slog.Info("клиент отключён", "user", userName, "remote", remote, "upload", up, "download", down)
	return nil
}

func remoteAddr(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return ""
	}
	return conn.RemoteAddr().String()
}

func relay(client io.ReadWriteCloser, server io.ReadWriteCloser) (upload, download int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(server, client)
		upload = n
		_ = server.Close()
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(client, server)
		download = n
		_ = client.Close()
	}()
	wg.Wait()
	return upload, download
}
