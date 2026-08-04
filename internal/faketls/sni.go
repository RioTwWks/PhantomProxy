package faketls

import (
	"strings"
	"sync"
	"time"
)

// SNIRotator выбирает SNI из пула по стратегии.
type SNIRotator struct {
	mu         sync.Mutex
	pool       []string
	strategy   string
	interval   time.Duration
	currentIdx int
	lastRotate time.Time
}

// NewSNIRotator создаёт ротатор SNI. Пустой пул — ротатор неактивен.
func NewSNIRotator(pool []string, strategy string, intervalSec int) *SNIRotator {
	clean := make([]string, 0, len(pool))
	for _, host := range pool {
		host = strings.TrimSpace(host)
		if host != "" {
			clean = append(clean, host)
		}
	}
	if len(clean) == 0 {
		return nil
	}
	if strategy == "" {
		strategy = RotationPerConnection
	}
	if intervalSec <= 0 {
		intervalSec = 300
	}
	return &SNIRotator{
		pool:       clean,
		strategy:   strategy,
		interval:   time.Duration(intervalSec) * time.Second,
		lastRotate: time.Now(),
	}
}

// Pick возвращает SNI из пула или fallback, если пул пуст.
func (r *SNIRotator) Pick(fallback string) string {
	if r == nil || len(r.pool) == 0 {
		return fallback
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	switch r.strategy {
	case RotationTimeBased:
		if time.Since(r.lastRotate) >= r.interval {
			r.currentIdx = (r.currentIdx + 1) % len(r.pool)
			r.lastRotate = time.Now()
		}
		return r.pool[r.currentIdx]
	default: // per_connection
		return r.pool[randInt(len(r.pool))]
	}
}
