package proxy

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
)

// RebindListenIfNeeded перепривязывает TCP-listener, если listen host/port изменились в конфиге.
func (s *Server) RebindListenIfNeeded() (bool, error) {
	want := s.rt.Snapshot().Addr()
	s.lnMu.RLock()
	cur := s.ln
	s.lnMu.RUnlock()

	if cur != nil && listenAddrsEqual(cur.Addr().String(), want) {
		return false, nil
	}

	newLn, err := net.Listen("tcp", want)
	if err != nil {
		return false, fmt.Errorf("listen %s: %w", want, err)
	}

	s.lnMu.Lock()
	old := s.ln
	s.ln = newLn
	s.lnMu.Unlock()

	if old != nil {
		_ = old.Close()
	}

	slog.Info("listen rebind", "addr", want)
	return true, nil
}

func (s *Server) acceptListener() net.Listener {
	s.lnMu.RLock()
	defer s.lnMu.RUnlock()
	return s.ln
}

func listenAddrsEqual(a, b string) bool {
	return normalizeListenAddr(a) == normalizeListenAddr(b)
}

func normalizeListenAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	switch host {
	case "", "0.0.0.0", "::", "::0":
		host = "*"
	}
	return net.JoinHostPort(host, port)
}
