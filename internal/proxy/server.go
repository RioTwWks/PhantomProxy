package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/RioTwWks/PhantomProxy/internal/config"
	"github.com/RioTwWks/PhantomProxy/internal/faketls"
	"github.com/RioTwWks/PhantomProxy/internal/fallback"
	"github.com/RioTwWks/PhantomProxy/internal/mtproto"
	"github.com/RioTwWks/PhantomProxy/internal/obfuscated2"
	"github.com/RioTwWks/PhantomProxy/internal/telegram"
)

// Server принимает TCP-соединения и маршрутизирует их.
type Server struct {
	cfg    config.Config
	secret mtproto.Secret
	ln     net.Listener
	wg     sync.WaitGroup
}

// New создаёт прокси-сервер.
func New(cfg config.Config, secret mtproto.Secret) *Server {
	return &Server{cfg: cfg, secret: secret}
}

// Serve запускает прослушивание до отмены контекста.
func (s *Server) Serve(ctx context.Context) error {
	var err error
	s.ln, err = net.Listen("tcp", s.cfg.Addr())
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.Addr(), err)
	}

	slog.Info("прокси слушает", "addr", s.cfg.Addr())

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
			_ = faketls.RedirectToDomain(conn, s.secret.Host)
		}
		return
	}

	slog.Debug("постороннее соединение", "remote", remote, "first_byte", fmt.Sprintf("0x%02x", first[0]))
	if err := fallback.Serve(conn, s.cfg.Fallback.Upstream); err != nil {
		slog.Debug("fallback завершился с ошибкой", "remote", remote, "err", err)
	}
}

func (s *Server) handleFakeTLS(ctx context.Context, conn net.Conn, first []byte) error {
	prefixed := &faketls.PrefixConn{Conn: conn, Prefix: first}

	ch, err := faketls.ReadClientHello(prefixed, s.secret.Key[:], s.secret.Host)
	if err != nil {
		return err
	}

	if err := faketls.WriteServerHello(conn, ch, s.secret.Key[:]); err != nil {
		return fmt.Errorf("server hello: %w", err)
	}

	tlsConn := &faketls.RecordConn{Conn: conn}
	obfConn, dcID, err := obfuscated2.Handshake(tlsConn, tlsConn, nil)
	if err != nil {
		return fmt.Errorf("obfuscated2: %w", err)
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}

	dcAddr, err := telegram.ResolveAddr(dcID, s.cfg.MTProto.Backend)
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

	slog.Info("клиент подключён", "remote", remoteAddr(conn), "dc", dcID, "backend", dcAddr)
	up, down := relay(clientConn, serverConn)
	slog.Info("клиент отключён", "remote", remoteAddr(conn), "upload", up, "download", down)
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
