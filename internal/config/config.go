package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/RioTwWks/PhantomProxy/internal/faketls"
	"github.com/RioTwWks/PhantomProxy/internal/mtproto"
	"github.com/RioTwWks/PhantomProxy/internal/user"
	"github.com/spf13/viper"
)

// Config описывает параметры прокси-сервера.
type Config struct {
	Listen     ListenConfig     `mapstructure:"listen" yaml:"listen"`
	MTProto    MTProtoConfig    `mapstructure:"mtproto" yaml:"mtproto"`
	TLS        TLSConfig        `mapstructure:"tls" yaml:"tls"`
	Fallback   FallbackConfig   `mapstructure:"fallback" yaml:"fallback"`
	Management ManagementConfig `mapstructure:"management" yaml:"management"`
	Fronting   FrontingConfig   `mapstructure:"fronting" yaml:"fronting"`
	Security   SecurityConfig   `mapstructure:"security" yaml:"security"`
	Protocols  ProtocolsConfig  `mapstructure:"protocols" yaml:"protocols"`
	Upstream   UpstreamConfig   `mapstructure:"upstream" yaml:"upstream"`
	Metrics    MetricsConfig    `mapstructure:"metrics" yaml:"metrics"`
}

// FrontingConfig — domain fronting при отклонённом Fake TLS.
type FrontingConfig struct {
	Enabled bool   `mapstructure:"enabled" yaml:"enabled"`
	Port    int    `mapstructure:"port" yaml:"port"`
	Action  string `mapstructure:"action" yaml:"action"` // splice, redirect, fallback
}

// SecurityConfig — anti-replay и лимиты.
type SecurityConfig struct {
	AntireplayCacheMB  int `mapstructure:"antireplay_cache_mb" yaml:"antireplay_cache_mb"`
	MaxConnectionsPerIP int `mapstructure:"max_connections_per_ip" yaml:"max_connections_per_ip"`
	HandshakeTimeoutSec int `mapstructure:"handshake_timeout_sec" yaml:"handshake_timeout_sec"`
}

// ProtocolsConfig — поддерживаемые режимы MTProto.
type ProtocolsConfig struct {
	FakeTLS bool `mapstructure:"fake_tls" yaml:"fake_tls"`
	Secure  bool `mapstructure:"secure" yaml:"secure"`
}

// UpstreamConfig — исходящие соединения к DC.
type UpstreamConfig struct {
	SOCKS5   string `mapstructure:"socks5" yaml:"socks5,omitempty"`
	PreferIP string `mapstructure:"prefer_ip" yaml:"prefer_ip"`
}

// MetricsConfig — Prometheus.
type MetricsConfig struct {
	Host string `mapstructure:"host" yaml:"host"`
	Port int    `mapstructure:"port" yaml:"port"`
}

// Enabled возвращает true, если metrics включены.
func (c MetricsConfig) Enabled() bool { return c.Port > 0 }

// Addr возвращает адрес metrics.
func (c MetricsConfig) Addr() string {
	host := c.Host
	if host == "" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("%s:%d", host, c.Port)
}

// ManagementConfig — HTTP API управления.
type ManagementConfig struct {
	Host                  string `mapstructure:"host" yaml:"host"`
	Port                  int    `mapstructure:"port" yaml:"port"`
	Token                 string `mapstructure:"token" yaml:"token"`
	PublicServer          string `mapstructure:"public_server" yaml:"public_server"`
	ServiceName           string `mapstructure:"service_name" yaml:"service_name"`
	ServiceUnitPath       string `mapstructure:"service_unit_path" yaml:"service_unit_path,omitempty"`
	AllowServiceUninstall bool   `mapstructure:"allow_service_uninstall" yaml:"allow_service_uninstall"`
	UninstallScript       string `mapstructure:"uninstall_script" yaml:"uninstall_script,omitempty"`
}

// Enabled возвращает true, если API управления включён.
func (c ManagementConfig) Enabled() bool {
	return c.Port > 0
}

// Addr возвращает адрес API управления.
func (c ManagementConfig) Addr() string {
	host := c.Host
	if host == "" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("%s:%d", host, c.Port)
}

// ListenConfig — адрес прослушивания.
type ListenConfig struct {
	Host          string `mapstructure:"host" yaml:"host"`
	Port          int    `mapstructure:"port" yaml:"port"`
	ProxyProtocol bool   `mapstructure:"proxy_protocol" yaml:"proxy_protocol"`
}

// UserConfig — пользователь MTProto-прокси.
type UserConfig struct {
	Name    string `mapstructure:"name" yaml:"name"`
	Secret  string `mapstructure:"secret" yaml:"secret"`
	Enabled *bool  `mapstructure:"enabled" yaml:"enabled"`
}

// MTProtoConfig — секреты и бэкенд Telegram.
type MTProtoConfig struct {
	Secret  string       `mapstructure:"secret" yaml:"secret,omitempty"`
	Backend string       `mapstructure:"backend" yaml:"backend"`
	Users   []UserConfig `mapstructure:"users" yaml:"users"`
}

// TLSConfig — параметры Fake TLS и отпечатков.
type TLSConfig struct {
	RecordMinChunk int      `mapstructure:"record_min_chunk" yaml:"record_min_chunk"`
	RecordMaxChunk int      `mapstructure:"record_max_chunk" yaml:"record_max_chunk"`
	NoiseMean      int      `mapstructure:"noise_mean" yaml:"noise_mean"`
	NoiseJitter    int      `mapstructure:"noise_jitter" yaml:"noise_jitter"`
	AllowedJA3     []string `mapstructure:"allowed_ja3" yaml:"allowed_ja3,omitempty"`
	AllowedJA4     []string `mapstructure:"allowed_ja4" yaml:"allowed_ja4,omitempty"`
	EnableDRS      bool     `mapstructure:"enable_drs" yaml:"enable_drs"`
	EnableSplitTLS bool     `mapstructure:"enable_split_tls" yaml:"enable_split_tls"`
}

// FallbackConfig — сайт-заглушка для посторонних соединений.
type FallbackConfig struct {
	Upstream string `mapstructure:"upstream" yaml:"upstream"`
}

// Addr возвращает адрес прослушивания в формате host:port.
func (c Config) Addr() string {
	host := c.Listen.Host
	if host == "" {
		host = "0.0.0.0"
	}
	return fmt.Sprintf("%s:%d", host, c.Listen.Port)
}

// HandshakeTimeout возвращает таймаут рукопожатия.
func (c Config) HandshakeTimeout() time.Duration {
	sec := c.Security.HandshakeTimeoutSec
	if sec <= 0 {
		sec = 10
	}
	return time.Duration(sec) * time.Second
}

// FrontingPort возвращает порт domain fronting.
func (c Config) FrontingPort() int {
	if c.Fronting.Port <= 0 {
		return 443
	}
	return c.Fronting.Port
}

// FrontingAction возвращает действие при отклонённом TLS.
func (c Config) FrontingAction() string {
	switch c.Fronting.Action {
	case "redirect", "fallback", "splice":
		return c.Fronting.Action
	}
	if c.Fronting.Enabled {
		return "splice"
	}
	return "redirect"
}

// RecordPolicy возвращает политику размера TLS-записей.
func (c Config) RecordPolicy() faketls.RecordPolicy {
	return faketls.RecordPolicy{
		MinChunk:       c.TLS.RecordMinChunk,
		MaxChunk:       c.TLS.RecordMaxChunk,
		EnableDRS:      c.TLS.EnableDRS,
		EnableSplitTLS: c.TLS.EnableSplitTLS,
	}.Normalize()
}

// NoiseParams возвращает параметры padding ServerHello.
func (c Config) NoiseParams() faketls.NoiseParams {
	return faketls.NoiseParams{
		Mean:   c.TLS.NoiseMean,
		Jitter: c.TLS.NoiseJitter,
	}
}

// AntireplayMaxEntries оценивает размер кеша anti-replay.
func (c Config) AntireplayMaxEntries() int {
	mb := c.Security.AntireplayCacheMB
	if mb <= 0 {
		mb = 1
	}
	return mb * 10000
}

// Load читает конфигурацию из файла и переменных окружения.
func Load(path string) (Config, *user.Manager, error) {
	cfg, err := loadFile(path)
	if err != nil {
		return Config{}, nil, err
	}

	users, err := buildUsers(cfg.MTProto)
	if err != nil {
		return Config{}, nil, err
	}

	mgr, err := user.NewManager(users, cfg.TLS.AllowedJA3, cfg.TLS.AllowedJA4)
	if err != nil {
		return Config{}, nil, err
	}

	return cfg, mgr, nil
}

// LoadUsers перечитывает только пользователей из файла.
func LoadUsers(path string) ([]user.User, error) {
	cfg, err := loadFile(path)
	if err != nil {
		return nil, err
	}
	return buildUsers(cfg.MTProto)
}

func loadFile(path string) (Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetEnvPrefix("PHANTOM")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	v.SetDefault("listen.host", "0.0.0.0")
	v.SetDefault("listen.port", 443)
	v.SetDefault("fallback.upstream", "http://127.0.0.1:8080")
	v.SetDefault("tls.record_min_chunk", 512)
	v.SetDefault("tls.record_max_chunk", 4096)
	v.SetDefault("tls.noise_mean", 3000)
	v.SetDefault("tls.noise_jitter", 800)
	v.SetDefault("tls.enable_drs", true)
	v.SetDefault("tls.enable_split_tls", true)
	v.SetDefault("management.host", "127.0.0.1")
	v.SetDefault("management.port", 8081)
	v.SetDefault("management.service_name", "phantom-proxy")
	v.SetDefault("management.allow_service_uninstall", false)
	v.SetDefault("fronting.enabled", true)
	v.SetDefault("fronting.port", 443)
	v.SetDefault("fronting.action", "splice")
	v.SetDefault("security.antireplay_cache_mb", 1)
	v.SetDefault("security.handshake_timeout_sec", 10)
	v.SetDefault("protocols.fake_tls", true)
	v.SetDefault("protocols.secure", true)
	v.SetDefault("upstream.prefer_ip", "prefer-ipv4")
	v.SetDefault("metrics.host", "127.0.0.1")
	v.SetDefault("metrics.port", 9090)

	if err := v.ReadInConfig(); err != nil {
		return Config{}, fmt.Errorf("чтение конфигурации: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return Config{}, fmt.Errorf("разбор конфигурации: %w", err)
	}
	return cfg, nil
}

func buildUsers(mt MTProtoConfig) ([]user.User, error) {
	configs := mt.Users
	if len(configs) == 0 {
		if mt.Secret == "" {
			return nil, fmt.Errorf("нужен mtproto.secret или mtproto.users")
		}
		configs = []UserConfig{{Name: "default", Secret: mt.Secret}}
	}

	users := make([]user.User, 0, len(configs))
	for _, item := range configs {
		if item.Secret == "" {
			return nil, fmt.Errorf("пользователь %q: secret обязателен", item.Name)
		}
		secret, err := mtproto.ParseSecret(item.Secret)
		if err != nil {
			return nil, fmt.Errorf("пользователь %q: %w", item.Name, err)
		}
		enabled := true
		if item.Enabled != nil {
			enabled = *item.Enabled
		}
		name := item.Name
		if name == "" {
			if secret.Host != "" {
				name = secret.Host
			} else {
				name = "user"
			}
		}
		users = append(users, user.User{
			Name:    name,
			Secret:  secret,
			Enabled: enabled,
		})
	}
	return users, nil
}
