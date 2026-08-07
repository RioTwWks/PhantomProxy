package faketls

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"
)

// Профили синтетического ServerHello (вариации extensions).
const (
	ServerProfileChrome = "chrome"
	ServerProfileFirefox = "firefox"
	ServerProfileEdge   = "edge"
	ServerProfileSafari = "safari"
)

var defaultServerHelloProfiles = []string{
	ServerProfileChrome,
	ServerProfileFirefox,
	ServerProfileEdge,
	ServerProfileSafari,
}

// ServerHelloRotator выбирает профиль ServerHello.
type ServerHelloRotator struct {
	mu                sync.Mutex
	profiles          []string
	strategy          string
	interval          time.Duration
	adaptiveThreshold int
	currentIdx        int
	lastRotate        time.Time
	failures          int
}

// NewServerHelloRotator создаёт ротатор ServerHello.
func NewServerHelloRotator(names []string, strategy string, intervalSec, adaptiveThreshold int) *ServerHelloRotator {
	if len(names) == 0 {
		names = defaultServerHelloProfiles
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
	return &ServerHelloRotator{
		profiles:          names,
		strategy:          strategy,
		interval:          time.Duration(intervalSec) * time.Second,
		adaptiveThreshold: adaptiveThreshold,
		lastRotate:        time.Now(),
	}
}

// Pick возвращает имя профиля для текущего соединения.
func (r *ServerHelloRotator) Pick() string {
	if r == nil || len(r.profiles) == 0 {
		return ServerProfileChrome
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	switch r.strategy {
	case RotationTimeBased:
		if time.Since(r.lastRotate) >= r.interval {
			r.currentIdx = (r.currentIdx + 1) % len(r.profiles)
			r.lastRotate = time.Now()
		}
		return r.profiles[r.currentIdx]
	case RotationAdaptive:
		return r.profiles[r.currentIdx]
	default:
		return r.profiles[randInt(len(r.profiles))]
	}
}

// RecordFailure для adaptive-стратегии.
func (r *ServerHelloRotator) RecordFailure() {
	if r == nil || r.strategy != RotationAdaptive {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures++
	if r.failures >= r.adaptiveThreshold {
		r.currentIdx = (r.currentIdx + 1) % len(r.profiles)
		r.failures = 0
		r.lastRotate = time.Now()
	}
}

// RecordSuccess сбрасывает счётчик adaptive.
func (r *ServerHelloRotator) RecordSuccess() {
	if r == nil || r.strategy != RotationAdaptive {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures = 0
}

func buildServerHello(ch *ClientHello, profile string) []byte {
	switch profile {
	case ServerProfileFirefox:
		return buildServerHelloFirefox(ch)
	case ServerProfileEdge:
		return buildServerHelloEdge(ch)
	case ServerProfileSafari:
		return buildServerHelloSafari(ch)
	default:
		return buildServerHelloChrome(ch)
	}
}

func buildServerHelloChrome(ch *ClientHello) []byte {
	var ext bytes.Buffer
	ext.Write([]byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}) // supported_versions TLS1.3
	writeKeyShare(&ext)
	return finalizeServerHello(ch, ext.Bytes())
}

func buildServerHelloFirefox(ch *ClientHello) []byte {
	var ext bytes.Buffer
	writeKeyShare(&ext)
	ext.Write([]byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04})
	ext.Write([]byte{0x00, 0x2d, 0x00, 0x02, 0x01, 0x01}) // psk_key_exchange_modes
	return finalizeServerHello(ch, ext.Bytes())
}

func buildServerHelloEdge(ch *ClientHello) []byte {
	var ext bytes.Buffer
	ext.Write([]byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04})
	ext.Write([]byte{0xff, 0x01, 0x00, 0x01, 0x00}) // renegotiation_info
	writeKeyShare(&ext)
	return finalizeServerHello(ch, ext.Bytes())
}

func buildServerHelloSafari(ch *ClientHello) []byte {
	var ext bytes.Buffer
	ext.Write([]byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04})
	writeKeyShare(&ext)
	ext.Write([]byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00}) // ec_point_formats
	return finalizeServerHello(ch, ext.Bytes())
}

func writeKeyShare(ext *bytes.Buffer) {
	pubKey := make([]byte, 32)
	_, _ = rand.Read(pubKey)
	keyShare := append([]byte{0x00, 0x1d, 0x00, 0x20}, pubKey...)
	ext.Write([]byte{0x00, 0x33})
	binary.Write(ext, binary.BigEndian, uint16(len(keyShare))) //nolint:errcheck
	ext.Write(keyShare)
}

func finalizeServerHello(ch *ClientHello, extPayload []byte) []byte {
	var hello bytes.Buffer
	hello.WriteByte(0x02)
	hello.Write([]byte{0, 0, 0})
	hello.Write([]byte{0x03, 0x03})

	serverRandom := make([]byte, 32)
	_, _ = rand.Read(serverRandom)
	hello.Write(serverRandom)

	hello.WriteByte(byte(len(ch.SessionID)))
	hello.Write(ch.SessionID)
	binary.Write(&hello, binary.BigEndian, ch.CipherSuite) //nolint:errcheck
	hello.WriteByte(0x00)

	binary.Write(&hello, binary.BigEndian, uint16(len(extPayload))) //nolint:errcheck
	hello.Write(extPayload)

	result := hello.Bytes()
	bodyLen := len(result) - 4
	result[1] = byte(bodyLen >> 16)
	result[2] = byte(bodyLen >> 8)
	result[3] = byte(bodyLen)
	return result
}
