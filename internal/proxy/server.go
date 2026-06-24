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
	"github.com/RioTwWks/PhantomProxy/internal/obfuscated2"
	"github.com/RioTwWks/PhantomProxy/internal/runtime"
	"github.com/RioTwWks/PhantomProxy/internal/telegram"
)

// Server принимает TCP-соединения и маршрутизирует их.
type Server struct {
	rt *runtime.Runtime
	ln net.Listener
	wg sync.WaitGroup
}

// New создаёт прокси-сервер.
func New(rt *runtime.Runtime) *Server {
	return &Server{rt: rt}
}

// Serve запускает прослушивание до отмены контекста.
func (s *Server) Serve(ctx context.Context) error {
	addr := s.rt.Snapshot().Addr()
	var err error
	s.ln, err = net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	slog.Info("прокси слушает",
		"addr", addr,
		"users", len(s.rt.Users.Users()),
	)

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

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(ctx, conn)
		}()
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

	remote := conn.RemoteAddr().String()
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		slog.Debug("не удалось установить deadline", "remote", remote, "err", err)
		return
	}

	first := make([]byte, 1)
	n, err := conn.Read(first)
	if err != nil || n == 0 {
		return
	}

	if faketls.IsHandshakeRecord(first[0]) {
		if err := s.handleFakeTLS(ctx, conn, first); err != nil {
			slog.Debug("fake TLS отклонён", "remote", remote, "err", err)
			_ = faketls.RedirectToDomain(conn, s.rt.Users.MaskHost())
		}
		return
	}

	slog.Debug("постороннее соединение", "remote", remote, "first_byte", fmt.Sprintf("0x%02x", first[0]))
	cfg := s.rt.Snapshot()
	if err := fallback.Serve(conn, cfg.Fallback.Upstream); err != nil {
		slog.Debug("fallback завершился с ошибкой", "remote", remote, "err", err)
	}
}

func (s *Server) handleFakeTLS(ctx context.Context, conn net.Conn, first []byte) error {
	prefixed := &faketls.PrefixConn{Conn: conn, Prefix: first}

	ch, err := faketls.ParseClientHello(prefixed)
	if err != nil {
		return err
	}

	matched, err := s.rt.Users.MatchClientHello(ch)
	if err != nil {
		return err
	}

	ja3 := faketls.JA3(ch.Raw)
	ja4 := faketls.JA4(ch.Raw)
	slog.Debug("TLS fingerprint",
		"user", matched.Name,
		"ja3", ja3,
		"ja4", ja4,
	)

	cfg := s.rt.Snapshot()
	if err := faketls.WriteServerHelloWithNoise(conn, ch, matched.Secret.Key[:], cfg.NoiseParams()); err != nil {
		return fmt.Errorf("server hello: %w", err)
	}

	tlsConn := &faketls.RecordConn{Conn: conn, Policy: cfg.RecordPolicy()}
	obfConn, dcID, err := obfuscated2.Handshake(tlsConn, tlsConn, nil)
	if err != nil {
		return fmt.Errorf("obfuscated2: %w", err)
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}

	dcAddr, err := telegram.ResolveAddr(dcID, cfg.MTProto.Backend)
	if err != nil {
		return err
	}

	dialer := net.Dialer{Timeout: 10 * time.Second}
	dcConn, err := dialer.DialContext(ctx, "tcp", dcAddr)
	if err != nil {
		return fmt.Errorf("подключение к DC %s: %w", dcAddr, err)
	}
	defer dcConn.Close()

	header, enc, dec, err := obfuscated2.OutgoingHeader(dcID)
	if err != nil {
		return err
	}
	if _, err := dcConn.Write(header); err != nil {
		return fmt.Errorf("отправка заголовка DC: %w", err)
	}

	serverConn := &obfuscated2.OutgoingConn{
		Conn:      dcConn,
		EncStream: enc,
		DecStream: dec,
	}

	clientConn := &obfuscated2.Conn{
		Conn:      tlsConn,
		EncStream: obfConn.EncStream,
		DecStream: obfConn.DecStream,
	}

	s.rt.Stats.OnConnect(matched.Name)
	defer s.rt.Stats.OnDisconnect(matched.Name)

	slog.Info("клиент подключён",
		"user", matched.Name,
		"remote", remoteAddr(conn),
		"dc", dcID,
		"backend", dcAddr,
		"ja3", ja3,
	)
	up, down := relay(clientConn, serverConn)
	s.rt.Stats.AddTraffic(matched.Name, up, down)
	slog.Info("клиент отключён",
		"user", matched.Name,
		"remote", remoteAddr(conn),
		"upload", up,
		"download", down,
	)
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
		n, err := io.Copy(server, client)
		upload = n
		if err != nil {
			_ = server.Close()
		}
	}()

	go func() {
		defer wg.Done()
		n, err := io.Copy(client, server)
		download = n
		if err != nil {
			_ = client.Close()
		}
	}()

	wg.Wait()
	return upload, download
}
