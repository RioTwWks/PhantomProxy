package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/RioTwWks/PhantomProxy/internal/config"
	"github.com/RioTwWks/PhantomProxy/internal/proxy"
)

func main() {
	configPath := flag.String("config", "configs/config.yaml", "путь к файлу конфигурации")
	flag.Parse()

	cfg, users, err := config.Load(*configPath)
	if err != nil {
		slog.Error("ошибка загрузки конфигурации", "err", err)
		os.Exit(1)
	}

	names := make([]string, 0, len(users.Users()))
	for _, u := range users.Users() {
		names = append(names, u.Name)
	}

	slog.Info("PhantomProxy запущен",
		"listen", cfg.Addr(),
		"users", names,
		"mask_host", users.MaskHost(),
		"fallback", cfg.Fallback.Upstream,
		"record_chunk", cfg.RecordPolicy(),
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := proxy.New(cfg, users)
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx)
	}()

	select {
	case <-ctx.Done():
		slog.Info("получен сигнал завершения")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("ошибка остановки", "err", err)
			os.Exit(1)
		}
	case err := <-errCh:
		if err != nil {
			slog.Error("сервер завершился с ошибкой", "err", err)
			os.Exit(1)
		}
	}
}
