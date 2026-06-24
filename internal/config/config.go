package config

import (
	"fmt"
	"strings"

	"github.com/RioTwWks/PhantomProxy/internal/mtproto"
	"github.com/spf13/viper"
)

// Config описывает параметры прокси-сервера.
type Config struct {
	Listen   ListenConfig   `mapstructure:"listen"`
	MTProto  MTProtoConfig  `mapstructure:"mtproto"`
	Fallback FallbackConfig `mapstructure:"fallback"`
}

// ListenConfig — адрес прослушивания.
type ListenConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

// MTProtoConfig — секрет и бэкенд Telegram.
type MTProtoConfig struct {
	Secret  string `mapstructure:"secret"`
	Backend string `mapstructure:"backend"`
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

// Load читает конфигурацию из файла и переменных окружения.
func Load(path string) (Config, mtproto.Secret, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetEnvPrefix("PHANTOM")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	v.SetDefault("listen.host", "0.0.0.0")
	v.SetDefault("listen.port", 443)
	v.SetDefault("fallback.upstream", "http://127.0.0.1:8080")

	if err := v.ReadInConfig(); err != nil {
		return Config{}, mtproto.Secret{}, fmt.Errorf("чтение конфигурации: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return Config{}, mtproto.Secret{}, fmt.Errorf("разбор конфигурации: %w", err)
	}

	if cfg.MTProto.Secret == "" {
		return Config{}, mtproto.Secret{}, fmt.Errorf("mtproto.secret обязателен")
	}

	secret, err := mtproto.ParseSecret(cfg.MTProto.Secret)
	if err != nil {
		return Config{}, mtproto.Secret{}, fmt.Errorf("некорректный секрет: %w", err)
	}

	return cfg, secret, nil
}
