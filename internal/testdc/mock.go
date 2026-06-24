package testdc

import (
	"io"
	"net"
	"sync"
	"time"
)

// Server имитирует Telegram DC: принимает obfuscated2 от прокси и эхо-отвечает.
type Server struct {
	ln       net.Listener
	wg       sync.WaitGroup
	Payloads chan []byte
}

// Start поднимает mock DC на 127.0.0.1:0.
func Start() (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{ln: ln, Payloads: make(chan []byte, 4)}
	s.wg.Add(1)
	go s.serve()
	return s, nil
}

// Addr возвращает адрес mock DC.
func (s *Server) Addr() string {
	return s.ln.Addr().String()
}

// Close останавливает сервер.
func (s *Server) Close() error {
	err := s.ln.Close()
	s.wg.Wait()
	return err
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer c.Close()
			_ = handleConn(c, s.Payloads)
		}(conn)
	}
}

func handleConn(conn net.Conn, payloads chan<- []byte) error {
	header := make([]byte, 64)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	dec := newCTR(copyBytes(header[8:40]), copyBytes(header[40:56]))
	advance := make([]byte, 64)
	dec.XORKeyStream(advance, advance)

	reversed := reverse(header)
	enc := newCTR(copyBytes(reversed[8:40]), copyBytes(reversed[40:56]))

	cipherData, err := readAvailable(conn, 300*time.Millisecond)
	if err != nil && len(cipherData) == 0 {
		return err
	}

	plain := make([]byte, len(cipherData))
	copy(plain, cipherData)
	dec.XORKeyStream(plain, plain)

	select {
	case payloads <- append([]byte(nil), plain...):
	default:
	}

	respCipher := make([]byte, len(plain))
	copy(respCipher, plain)
	enc.XORKeyStream(respCipher, respCipher)

	_, err = conn.Write(respCipher)
	return err
}

func readAvailable(conn net.Conn, idle time.Duration) ([]byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(idle))
	var out []byte
	buf := make([]byte, 8192)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
			_ = conn.SetReadDeadline(time.Now().Add(idle))
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return out, nil
			}
			if err == io.EOF {
				return out, nil
			}
			return out, err
		}
	}
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

func copyBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
