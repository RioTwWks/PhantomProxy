package middleproxy

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// DefaultProxySecret — fallback secret с core.telegram.org/getProxySecret.
var DefaultProxySecret = mustHex(
	"c4f9faca9678e6bb48ad6c7e2ce5c0d24430645d554addeb55419e034da62721" +
		"d046eaab6e52ab14a95a443ecfb3463e79a05a66612adf9caeda8be9a80da698" +
		"6fb0a6ff387af84d88ef3a6413713e5c3377f6e1a3d47d99f5e0c56eece8f05c" +
		"54c490b079e31bef82ff0ee8f2b0a32756d249c5f21269816cb7061b265db212",
)

// DefaultProxiesV4 — middle proxy endpoints по DC (обновляются с getProxyConfig).
var DefaultProxiesV4 = map[int][]Endpoint{
	1:  {{Host: "149.154.175.50", Port: 8888}},
	-1: {{Host: "149.154.175.50", Port: 8888}},
	2:  {{Host: "149.154.161.144", Port: 8888}},
	-2: {{Host: "149.154.161.144", Port: 8888}},
	3:  {{Host: "149.154.175.100", Port: 8888}},
	-3: {{Host: "149.154.175.100", Port: 8888}},
	4:  {{Host: "91.108.4.136", Port: 8888}},
	-4: {{Host: "149.154.165.109", Port: 8888}},
	5:  {{Host: "91.108.56.183", Port: 8888}},
	-5: {{Host: "91.108.56.183", Port: 8888}},
}

// Endpoint — адрес middle proxy Telegram.
type Endpoint struct {
	Host string
	Port int
}

func (e Endpoint) String() string {
	return fmt.Sprintf("%s:%d", e.Host, e.Port)
}

// ParseAdTag разбирает 32-символьный hex-тег от @MTProxybot.
func ParseAdTag(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if len(s) != 32 {
		return nil, fmt.Errorf("ad_tag: нужно 32 hex-символа, получено %d", len(s))
	}
	tag, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("ad_tag: %w", err)
	}
	return tag, nil
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// ResolveEndpoints возвращает список ME для DC.
func ResolveEndpoints(dcID int) []Endpoint {
	id := dcID
	if id == 0 {
		id = 2
	}
	if eps, ok := DefaultProxiesV4[id]; ok && len(eps) > 0 {
		return eps
	}
	if eps, ok := DefaultProxiesV4[-id]; ok {
		return eps
	}
	return nil
}
