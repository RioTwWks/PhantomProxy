package config

import (
	"fmt"
	"strings"

	"github.com/RioTwWks/PhantomProxy/internal/faketls"
	"github.com/RioTwWks/PhantomProxy/internal/mtproto"
	"github.com/RioTwWks/PhantomProxy/internal/user"
	"github.com/spf13/viper"
)

// Config описывает параметры прокси-сервера.
type Config struct {
	Listen      ListenConfig      `mapstructure:"listen"`
	MTProto     MTProtoConfig     `mapstructure:"mtproto"`
	TLS         TLSConfig         `mapstructure:"tls"`
	Fallback    FallbackConfig    `mapstructure:"fallback"`
	Management  ManagementConfig  `mapstructure:"management"`
}

// ManagementConfig — HTTP API управления.
type ManagementConfig struct {
	Host  string `mapstructure:"host"`
	Port  int    `mapstructure:"port"`
	Token string `mapstructure:"token"`
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
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

// UserConfig — пользователь MTProto-прокси.
type UserConfig struct {
	Name    string `mapstructure:"name"`
	Secret  string `mapstructure:"secret"`
	Enabled *bool  `mapstructure:"enabled"`
}

// MTProtoConfig — секреты и бэкенд Telegram.
type MTProtoConfig struct {
	Secret  string       `mapstructure:"secret"`
	Backend string       `mapstructure:"backend"`
	Users   []UserConfig `mapstructure:"users"`
}

// TLSConfig — параметры Fake TLS и отпечатков.
type TLSConfig struct {
	RecordMinChunk int      `mapstructure:"record_min_chunk"`
	RecordMaxChunk int      `mapstructure:"record_max_chunk"`
	NoiseMean      int      `mapstructure:"noise_mean"`
	NoiseJitter    int      `mapstructure:"noise_jitter"`
	AllowedJA3     []string `mapstructure:"allowed_ja3"`
}

// FallbackConfig — сайт-заглушка для посторонних соединений.
type FallbackConfig struct {
	Upstream string `mapstructure:"upstream"`
}

// Addr возвращает адрес прослушивания в формате host:port.
func (c Config) Addr() string {
	host := c.Listen.Host
	if host == "" {
		host = "0.0.0.0"
	}
	return fmt.Sprintf("%s:%d", host, c.Listen.Port)
}

// RecordPolicy возвращает политику размера TLS-записей.
func (c Config) RecordPolicy() faketls.RecordPolicy {
	return faketls.RecordPolicy{
		MinChunk: c.TLS.RecordMinChunk,
		MaxChunk: c.TLS.RecordMaxChunk,
	}.Normalize()
}

// NoiseParams возвращает параметры padding ServerHello.
func (c Config) NoiseParams() faketls.NoiseParams {
	return faketls.NoiseParams{
		Mean:   c.TLS.NoiseMean,
		Jitter: c.TLS.NoiseJitter,
	}
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

	mgr, err := user.NewManager(users, cfg.TLS.AllowedJA3)
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
	v.SetDefault("management.host", "127.0.0.1")
	v.SetDefault("management.port", 8081)

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
			name = secret.Host
		}
		users = append(users, user.User{
			Name:    name,
			Secret:  secret,
			Enabled: enabled,
		})
	}
	return users, nil
}
