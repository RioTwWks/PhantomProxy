package config

import (
	"fmt"
	"os"

	"github.com/RioTwWks/PhantomProxy/internal/mtproto"
	"github.com/RioTwWks/PhantomProxy/internal/user"
	"gopkg.in/yaml.v3"
)

// SettingsView — настройки прокси для UI/API.
type SettingsView struct {
	ListenHost       string   `json:"listen_host" yaml:"listen_host"`
	ListenPort       int      `json:"listen_port" yaml:"listen_port"`
	Backend          string   `json:"backend" yaml:"backend"`
	FallbackUpstream string   `json:"fallback_upstream" yaml:"fallback_upstream"`
	RecordMinChunk   int      `json:"record_min_chunk" yaml:"record_min_chunk"`
	RecordMaxChunk   int      `json:"record_max_chunk" yaml:"record_max_chunk"`
	NoiseMean        int      `json:"noise_mean" yaml:"noise_mean"`
	NoiseJitter      int      `json:"noise_jitter" yaml:"noise_jitter"`
	AllowedJA3       []string `json:"allowed_ja3" yaml:"allowed_ja3"`
	PublicServer     string   `json:"public_server" yaml:"public_server"`
}

// SettingsFromConfig собирает view из конфигурации.
func SettingsFromConfig(cfg Config) SettingsView {
	return SettingsView{
		ListenHost:       cfg.Listen.Host,
		ListenPort:       cfg.Listen.Port,
		Backend:          cfg.MTProto.Backend,
		FallbackUpstream: cfg.Fallback.Upstream,
		RecordMinChunk:   cfg.TLS.RecordMinChunk,
		RecordMaxChunk:   cfg.TLS.RecordMaxChunk,
		NoiseMean:        cfg.TLS.NoiseMean,
		NoiseJitter:      cfg.TLS.NoiseJitter,
		AllowedJA3:       cfg.TLS.AllowedJA3,
		PublicServer:     cfg.Management.PublicServer,
	}
}

// ApplySettings применяет изменения к конфигурации.
func ApplySettings(cfg Config, s SettingsView) Config {
	cfg.Listen.Host = s.ListenHost
	cfg.Listen.Port = s.ListenPort
	cfg.MTProto.Backend = s.Backend
	cfg.Fallback.Upstream = s.FallbackUpstream
	cfg.TLS.RecordMinChunk = s.RecordMinChunk
	cfg.TLS.RecordMaxChunk = s.RecordMaxChunk
	cfg.TLS.NoiseMean = s.NoiseMean
	cfg.TLS.NoiseJitter = s.NoiseJitter
	cfg.TLS.AllowedJA3 = s.AllowedJA3
	cfg.Management.PublicServer = s.PublicServer
	return cfg
}

// UsersToConfig конвертирует пользователей в формат YAML.
func UsersToConfig(users []user.User) []UserConfig {
	out := make([]UserConfig, 0, len(users))
	for _, u := range users {
		enabled := u.Enabled
		out = append(out, UserConfig{
			Name:    u.Name,
			Secret:  mtproto.EncodeHex(u.Secret),
			Enabled: &enabled,
		})
	}
	return out
}
func Save(path string, cfg Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("сериализация конфигурации: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("запись конфигурации: %w", err)
	}
	return nil
}
