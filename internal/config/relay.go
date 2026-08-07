package config

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// RelayConfig — Front/Back туннель между серверами.
type RelayConfig struct {
	Mode       string `mapstructure:"mode" yaml:"mode"` // off, front, back
	PeerAddr   string `mapstructure:"peer_addr" yaml:"peer_addr,omitempty"`
	ListenHost string `mapstructure:"listen_host" yaml:"listen_host,omitempty"`
	ListenPort int    `mapstructure:"listen_port" yaml:"listen_port,omitempty"`
	PSK        string `mapstructure:"psk" yaml:"psk,omitempty"`
}

// Enabled возвращает true, если relay активен.
func (c RelayConfig) Enabled() bool {
	return c.Mode == "front" || c.Mode == "back"
}

// IsFront возвращает true для front-режима.
func (c RelayConfig) IsFront() bool { return c.Mode == "front" }

// IsBack возвращает true для back-режима.
func (c RelayConfig) IsBack() bool { return c.Mode == "back" }

// ListenAddr возвращает адрес relay listener (back).
func (c RelayConfig) ListenAddr() string {
	host := c.ListenHost
	if host == "" {
		host = "0.0.0.0"
	}
	port := c.ListenPort
	if port <= 0 {
		port = 15443
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// PSKBytes декодирует PSK из hex.
func (c RelayConfig) PSKBytes() ([]byte, error) {
	s := strings.TrimSpace(c.PSK)
	if s == "" {
		return nil, fmt.Errorf("relay.psk обязателен при relay.mode=%s", c.Mode)
	}
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("relay.psk: %w", err)
	}
	if len(key) < 16 {
		return nil, fmt.Errorf("relay.psk слишком короткий (минимум 16 байт hex)")
	}
	return key, nil
}
