package limit

import (
	"net"
	"sync"
)

// ConnLimiter ограничивает число одновременных соединений с одного IP.
type ConnLimiter struct {
	mu     sync.Mutex
	max    int
	counts map[string]int
}

// NewConnLimiter создаёт лимитер. max <= 0 — без лимита.
func NewConnLimiter(max int) *ConnLimiter {
	return &ConnLimiter{
		max:    max,
		counts: make(map[string]int),
	}
}

// Acquire пытается занять слот для IP.
func (l *ConnLimiter) Acquire(conn net.Conn) bool {
	if l == nil || l.max <= 0 {
		return true
	}
	ip := clientIP(conn)
	if ip == "" {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.counts[ip] >= l.max {
		return false
	}
	l.counts[ip]++
	return true
}

// Release освобождает слот для IP.
func (l *ConnLimiter) Release(conn net.Conn) {
	if l == nil || l.max <= 0 {
		return
	}
	ip := clientIP(conn)
	if ip == "" {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.counts[ip] <= 1 {
		delete(l.counts, ip)
		return
	}
	l.counts[ip]--
}

func clientIP(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}
