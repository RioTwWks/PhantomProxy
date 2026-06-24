package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/RioTwWks/PhantomProxy/internal/admin"
	"github.com/RioTwWks/PhantomProxy/internal/config"
	"github.com/RioTwWks/PhantomProxy/internal/proxy"
	"github.com/RioTwWks/PhantomProxy/internal/runtime"
	"github.com/RioTwWks/PhantomProxy/internal/stats"
)

func main() {
	configPath := flag.String("config", "configs/config.yaml", "путь к файлу конфигурации")
	flag.Parse()

	cfg, users, err := config.Load(*configPath)
	if err != nil {
		slog.Error("ошибка загрузки конфигурации", "err", err)
		os.Exit(1)
	}

	tracker := stats.New()
	rt := runtime.New(*configPath, cfg, users, tracker)

	names := make([]string, 0, len(users.Users()))
	for _, u := range users.Users() {
		names = append(names, u.Name)
	}

	slog.Info("PhantomProxy запущен",
		"listen", cfg.Addr(),
		"users", names,
		"mask_host", users.MaskHost(),
		"fallback", cfg.Fallback.Upstream,
		"management", cfg.Management.Addr(),
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	proxySrv := proxy.New(rt)
	adminSrv := admin.New(rt, cfg.Management)

	errCh := make(chan error, 2)
	go func() { errCh <- proxySrv.Serve(ctx) }()
	if cfg.Management.Enabled() {
		go func() { errCh <- adminSrv.Serve(ctx) }()
	} else {
		slog.Warn("API управления отключён (management.port=0)")
	}

	select {
	case <-ctx.Done():
		slog.Info("получен сигнал завершения")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := proxySrv.Shutdown(shutdownCtx); err != nil {
			slog.Error("ошибка остановки прокси", "err", err)
			os.Exit(1)
		}
	case err := <-errCh:
		if err != nil {
			slog.Error("сервер завершился с ошибкой", "err", err)
			os.Exit(1)
		}
	}
}
