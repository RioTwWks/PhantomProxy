package runtime

import (
	"fmt"
	"sync"
	"time"

	"github.com/RioTwWks/PhantomProxy/internal/config"
	"github.com/RioTwWks/PhantomProxy/internal/faketls"
	"github.com/RioTwWks/PhantomProxy/internal/limit"
	"github.com/RioTwWks/PhantomProxy/internal/probe"
	"github.com/RioTwWks/PhantomProxy/internal/stats"
	"github.com/RioTwWks/PhantomProxy/internal/user"
)

// Runtime — общее состояние прокси и API управления.
type Runtime struct {
	mu                 sync.RWMutex
	ConfigPath         string
	Config             config.Config
	Users              *user.Manager
	Stats              *stats.Tracker
	Replay             *faketls.ReplayCache
	Limiter            *limit.ConnLimiter
	FingerprintRotator *faketls.FingerprintRotator
	ServerHelloRotator *faketls.ServerHelloRotator
	SNIRotator         *faketls.SNIRotator
	ProbeBlacklist     *probe.Blacklist
	StartedAt          time.Time
}

// New создаёт runtime.
func New(configPath string, cfg config.Config, users *user.Manager, tracker *stats.Tracker) *Runtime {
	rt := &Runtime{
		ConfigPath: configPath,
		Config:     cfg,
		Users:      users,
		Stats:      tracker,
		Replay:     faketls.NewReplayCache(cfg.AntireplayMaxEntries(), 2*time.Minute),
		Limiter:    limit.NewConnLimiter(cfg.Security.MaxConnectionsPerIP),
		StartedAt:  time.Now(),
	}
	rt.applySecurityFeatures(cfg)
	return rt
}

func (r *Runtime) applySecurityFeatures(cfg config.Config) {
	fp, err := faketls.NewFingerprintRotator(
		cfg.TLS.FingerprintPool,
		cfg.TLS.FingerprintRotation,
		cfg.TLS.FingerprintRotationInterval,
		cfg.TLS.FingerprintAdaptiveThreshold,
	)
	if err != nil {
		fp, _ = faketls.NewFingerprintRotator(nil, faketls.RotationPerConnection, 300, 20)
	}
	r.FingerprintRotator = fp
	r.ServerHelloRotator = faketls.NewServerHelloRotator(
		cfg.TLS.ServerHelloPool,
		cfg.TLS.ServerHelloRotation,
		cfg.TLS.ServerHelloRotationInterval,
		cfg.TLS.ServerHelloAdaptiveThreshold,
	)
	r.SNIRotator = faketls.NewSNIRotator(cfg.TLS.SNIPool, cfg.TLS.SNIRotation, cfg.TLS.SNIRotationInterval)
	r.ProbeBlacklist = probe.NewBlacklist(
		cfg.Security.ProbeBlacklistThreshold,
		cfg.Security.ProbeBlacklistDurationSec,
		cfg.Security.ProbeBlacklistWindowSec,
	)
}

// PickMaskSNI возвращает SNI для fronting/fallback с учётом пула.
func (r *Runtime) PickMaskSNI(fallback string) string {
	if r.SNIRotator != nil {
		return r.SNIRotator.Pick(fallback)
	}
	return fallback
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
	r.applySecurityFeatures(cfg)
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
		r.applySecurityFeatures(cfg)
		return nil
	}
	if err := config.Save(r.ConfigPath, cfg); err != nil {
		return err
	}
	r.Config = cfg
	r.applySecurityFeatures(cfg)
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
