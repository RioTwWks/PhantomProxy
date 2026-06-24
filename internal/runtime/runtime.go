package runtime

import (
	"fmt"
	"sync"
	"time"

	"github.com/RioTwWks/PhantomProxy/internal/config"
	"github.com/RioTwWks/PhantomProxy/internal/faketls"
	"github.com/RioTwWks/PhantomProxy/internal/limit"
	"github.com/RioTwWks/PhantomProxy/internal/stats"
	"github.com/RioTwWks/PhantomProxy/internal/user"
)

// Runtime — общее состояние прокси и API управления.
type Runtime struct {
	mu         sync.RWMutex
	ConfigPath string
	Config     config.Config
	Users      *user.Manager
	Stats      *stats.Tracker
	Replay     *faketls.ReplayCache
	Limiter    *limit.ConnLimiter
	StartedAt  time.Time
}

// New создаёт runtime.
func New(configPath string, cfg config.Config, users *user.Manager, tracker *stats.Tracker) *Runtime {
	return &Runtime{
		ConfigPath: configPath,
		Config:     cfg,
		Users:      users,
		Stats:      tracker,
		Replay:     faketls.NewReplayCache(cfg.AntireplayMaxEntries(), 2*time.Minute),
		Limiter:    limit.NewConnLimiter(cfg.Security.MaxConnectionsPerIP),
		StartedAt:  time.Now(),
	}
}

// Snapshot возвращает копию конфигурации.
func (r *Runtime) Snapshot() config.Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.Config
}

// UpdateConfig обновляет конфигурацию.
func (r *Runtime) UpdateConfig(cfg config.Config) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Config = cfg
}

// Reload перечитывает конфигурацию с диска.
func (r *Runtime) Reload() error {
	cfg, newMgr, err := config.Load(r.ConfigPath)
	if err != nil {
		return fmt.Errorf("перезагрузка конфигурации: %w", err)
	}
	if err := r.Users.Reload(newMgr.Users()); err != nil {
		return err
	}
	r.Users.SetFingerprints(cfg.TLS.AllowedJA3, cfg.TLS.AllowedJA4)
	r.UpdateConfig(cfg)
	r.Limiter = limit.NewConnLimiter(cfg.Security.MaxConnectionsPerIP)
	r.Replay = faketls.NewReplayCache(cfg.AntireplayMaxEntries(), 2*time.Minute)
	return nil
}

// UpdateSettings обновляет настройки и сохраняет конфигурацию на диск.
func (r *Runtime) UpdateSettings(settings config.SettingsView) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	cfg := config.ApplySettings(r.Config, settings)
	cfg.MTProto.Users = config.UsersToConfig(r.Users.Users())
	cfg.MTProto.Secret = ""

	r.Users.SetFingerprints(settings.AllowedJA3, settings.AllowedJA4)
	r.Limiter = limit.NewConnLimiter(settings.MaxConnectionsPerIP)

	if r.ConfigPath == "" {
		r.Config = cfg
		return nil
	}
	if err := config.Save(r.ConfigPath, cfg); err != nil {
		return err
	}
	r.Config = cfg
	return nil
}

// PersistUsers сохраняет текущих пользователей в конфиг на диск.
func (r *Runtime) PersistUsers() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.ConfigPath == "" {
		return nil
	}
	cfg := r.Config
	cfg.MTProto.Users = config.UsersToConfig(r.Users.Users())
	cfg.MTProto.Secret = ""
	if err := config.Save(r.ConfigPath, cfg); err != nil {
		return err
	}
	r.Config = cfg
	return nil
}

// Uptime возвращает время работы сервера.
func (r *Runtime) Uptime() time.Duration {
	return time.Since(r.StartedAt)
}
