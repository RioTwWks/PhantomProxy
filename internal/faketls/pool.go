package faketls

import (
	"fmt"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Стратегии ротации TLS-отпечатков.
const (
	RotationPerConnection = "per_connection"
	RotationTimeBased     = "time_based"
	RotationAdaptive      = "adaptive"
)

// DefaultFingerprintNames — пул актуальных браузерных отпечатков (utls v1.6.7).
var DefaultFingerprintNames = []string{
	"chrome_auto",
	"chrome_120",
	"chrome_120_pq",
	"firefox_auto",
	"firefox_120",
	"edge_auto",
	"safari_auto",
}

// fingerprintRegistry сопоставляет имена конфига с utls ClientHelloID.
var fingerprintRegistry = map[string]utls.ClientHelloID{
	"chrome_auto":        utls.HelloChrome_Auto,
	"chrome_120":         utls.HelloChrome_120,
	"chrome_120_pq":      utls.HelloChrome_120_PQ,
	"chrome_115_pq":      utls.HelloChrome_115_PQ,
	"chrome_106_shuffle": utls.HelloChrome_106_Shuffle,
	"firefox_auto":       utls.HelloFirefox_Auto,
	"firefox_120":        utls.HelloFirefox_120,
	"firefox_105":        utls.HelloFirefox_105,
	"edge_auto":          utls.HelloEdge_Auto,
	"edge_106":           utls.HelloEdge_106,
	"safari_auto":        utls.HelloSafari_Auto,
	"safari_16_0":        utls.HelloSafari_16_0,
}

// ParseFingerprint возвращает utls ClientHelloID по имени из конфига.
func ParseFingerprint(name string) (utls.ClientHelloID, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		return utls.ClientHelloID{}, fmt.Errorf("пустое имя отпечатка")
	}
	if id, ok := fingerprintRegistry[key]; ok {
		return id, nil
	}
	return utls.ClientHelloID{}, fmt.Errorf("неизвестный отпечаток %q", name)
}

// ParseFingerprintPool разбирает список имён; пустой список — DefaultFingerprintNames.
func ParseFingerprintPool(names []string) ([]utls.ClientHelloID, []string, error) {
	if len(names) == 0 {
		names = DefaultFingerprintNames
	}
	ids := make([]utls.ClientHelloID, 0, len(names))
	validNames := make([]string, 0, len(names))
	for _, name := range names {
		id, err := ParseFingerprint(name)
		if err != nil {
			return nil, nil, err
		}
		ids = append(ids, id)
		validNames = append(validNames, strings.ToLower(strings.TrimSpace(name)))
	}
	return ids, validNames, nil
}

// FingerprintRotator выбирает TLS-отпечаток по стратегии.
type FingerprintRotator struct {
	mu                sync.Mutex
	pool              []utls.ClientHelloID
	names             []string
	strategy          string
	interval          time.Duration
	adaptiveThreshold int
	currentIdx        int
	lastRotate        time.Time
	failures          int
}

// NewFingerprintRotator создаёт ротатор отпечатков.
func NewFingerprintRotator(names []string, strategy string, intervalSec, adaptiveThreshold int) (*FingerprintRotator, error) {
	ids, validNames, err := ParseFingerprintPool(names)
	if err != nil {
		return nil, err
	}
	if strategy == "" {
		strategy = RotationPerConnection
	}
	if intervalSec <= 0 {
		intervalSec = 300
	}
	if adaptiveThreshold <= 0 {
		adaptiveThreshold = 20
	}
	return &FingerprintRotator{
		pool:              ids,
		names:             validNames,
		strategy:          strategy,
		interval:          time.Duration(intervalSec) * time.Second,
		adaptiveThreshold: adaptiveThreshold,
		lastRotate:        time.Now(),
	}, nil
}

// Pick возвращает отпечаток для текущего соединения/интервала.
func (r *FingerprintRotator) Pick() utls.ClientHelloID {
	if r == nil || len(r.pool) == 0 {
		return utls.HelloChrome_Auto
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
	case RotationAdaptive:
		return r.pool[r.currentIdx]
	default: // per_connection
		idx := randInt(len(r.pool))
		return r.pool[idx]
	}
}

// CurrentName возвращает имя текущего отпечатка (для time_based/adaptive).
func (r *FingerprintRotator) CurrentName() string {
	if r == nil || len(r.names) == 0 {
		return "chrome_auto"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.names[r.currentIdx]
}

// RecordFailure увеличивает счётчик ошибок; при adaptive — ротирует отпечаток.
func (r *FingerprintRotator) RecordFailure() {
	if r == nil || r.strategy != RotationAdaptive {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures++
	if r.failures >= r.adaptiveThreshold {
		r.currentIdx = (r.currentIdx + 1) % len(r.pool)
		r.failures = 0
		r.lastRotate = time.Now()
	}
}

// RecordSuccess сбрасывает счётчик ошибок adaptive-стратегии.
func (r *FingerprintRotator) RecordSuccess() {
	if r == nil || r.strategy != RotationAdaptive {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures = 0
}
