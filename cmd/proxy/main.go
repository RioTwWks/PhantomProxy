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

	cfg, secret, err := config.Load(*configPath)
	if err != nil {
		slog.Error("ошибка загрузки конфигурации", "err", err)
		os.Exit(1)
	}

	slog.Info("PhantomProxy запущен",
		"listen", cfg.Addr(),
		"mask_host", secret.Host,
		"fallback", cfg.Fallback.Upstream,
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := proxy.New(cfg, secret)
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
