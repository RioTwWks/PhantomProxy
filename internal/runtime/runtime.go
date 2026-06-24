package runtime

import (
	"fmt"
	"sync"
	"time"

	"github.com/RioTwWks/PhantomProxy/internal/config"
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
	StartedAt  time.Time
}

// New создаёт runtime.
func New(configPath string, cfg config.Config, users *user.Manager, tracker *stats.Tracker) *Runtime {
	return &Runtime{
		ConfigPath: configPath,
		Config:     cfg,
		Users:      users,
		Stats:      tracker,
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
	r.UpdateConfig(cfg)
	return nil
}

// Uptime возвращает время работы сервера.
func (r *Runtime) Uptime() time.Duration {
	return time.Since(r.StartedAt)
}
