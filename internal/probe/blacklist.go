package probe

import (
	"net"
	"sync"
	"time"
)

// Blacklist блокирует IP с большим числом невалидных подключений (скользящее окно).
type Blacklist struct {
	mu        sync.Mutex
	threshold int
	duration  time.Duration
	window    time.Duration
	counts    map[string][]time.Time
	blocked   map[string]time.Time
}

// NewBlacklist создаёт blacklist. threshold <= 0 — отключён.
func NewBlacklist(threshold, durationSec, windowSec int) *Blacklist {
	if threshold <= 0 {
		return nil
	}
	if durationSec <= 0 {
		durationSec = 3600
	}
	if windowSec <= 0 {
		windowSec = 600
	}
	return &Blacklist{
		threshold: threshold,
		duration:  time.Duration(durationSec) * time.Second,
		window:    time.Duration(windowSec) * time.Second,
		counts:    make(map[string][]time.Time),
		blocked:   make(map[string]time.Time),
	}
}

// IsBlocked проверяет, заблокирован ли IP.
func (b *Blacklist) IsBlocked(ip string) bool {
	if b == nil || ip == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.purgeExpiredLocked()
	if until, ok := b.blocked[ip]; ok {
		if time.Now().Before(until) {
			return true
		}
		delete(b.blocked, ip)
		delete(b.counts, ip)
	}
	return false
}

// RecordProbe регистрирует невалидное подключение; возвращает true, если IP заблокирован.
func (b *Blacklist) RecordProbe(ip string) bool {
	if b == nil || ip == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.purgeExpiredLocked()

	if until, ok := b.blocked[ip]; ok && time.Now().Before(until) {
		return true
	}

	now := time.Now()
	cutoff := now.Add(-b.window)
	times := b.counts[ip]
	pruned := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	pruned = append(pruned, now)
	b.counts[ip] = pruned

	if len(pruned) >= b.threshold {
		b.blocked[ip] = now.Add(b.duration)
		delete(b.counts, ip)
		return true
	}
	return false
}

func (b *Blacklist) purgeExpiredLocked() {
	now := time.Now()
	for ip, until := range b.blocked {
		if now.After(until) {
			delete(b.blocked, ip)
			delete(b.counts, ip)
		}
	}
}

// ClientIP извлекает IP из net.Conn.
func ClientIP(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}
