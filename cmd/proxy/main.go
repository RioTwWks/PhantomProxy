package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/RioTwWks/PhantomProxy/internal/admin"
	"github.com/RioTwWks/PhantomProxy/internal/config"
	"github.com/RioTwWks/PhantomProxy/internal/metrics"
	"github.com/RioTwWks/PhantomProxy/internal/proxy"
	"github.com/RioTwWks/PhantomProxy/internal/runtime"
	"github.com/RioTwWks/PhantomProxy/internal/service"
	"github.com/RioTwWks/PhantomProxy/internal/stats"
	"github.com/RioTwWks/PhantomProxy/internal/user"
)

const version = "0.2.0"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "run":
			runServer(parseRunFlags(os.Args[2:]))
			return
		case "generate":
			cmdGenerate(os.Args[2:])
			return
		case "uninstall":
			cmdUninstall(os.Args[2:])
			return
		case "version", "-version":
			fmt.Println("telegram-proxy", version)
			return
		case "help", "-h", "--help":
			printUsage()
			return
		}
		if os.Args[1][0] == '-' {
			legacyRun(os.Args[1:])
			return
		}
	}

	runServer(runFlags{configPath: "configs/config.yaml"})
}

type runFlags struct {
	configPath string
}

func parseRunFlags(args []string) runFlags {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfg := fs.String("config", "configs/config.yaml", "путь к конфигурации")
	_ = fs.Parse(args)
	return runFlags{configPath: *cfg}
}

func legacyRun(args []string) {
	fs := flag.NewFlagSet("telegram-proxy", flag.ExitOnError)
	cfg := fs.String("config", "configs/config.yaml", "путь к файлу конфигурации")
	_ = fs.Parse(args)
	runServer(runFlags{configPath: *cfg})
}

func printUsage() {
	fmt.Println(`PhantomProxy — Fake TLS MTProto-прокси

Использование:
  telegram-proxy run [-config path]   Запустить прокси
  telegram-proxy generate <host>      Сгенерировать ee/dd секреты
  telegram-proxy uninstall [--purge]  Удалить systemd-сервис
  telegram-proxy version              Версия
  telegram-proxy -config path         Запуск (legacy)`)
}

func cmdGenerate(args []string) {
	host := "storage.googleapis.com"
	if len(args) > 0 {
		host = args[0]
	}
	secret, hex, err := user.GenerateSecret(host)
	if err != nil {
		slog.Error("генерация секрета", "err", err)
		os.Exit(1)
	}
	fmt.Printf("host=%s\n", secret.Host)
	fmt.Printf("ee_secret=%s\n", hex)
	_, ddHex, err := user.GenerateSecureSecret()
	if err != nil {
		slog.Error("генерация dd-секрета", "err", err)
		os.Exit(1)
	}
	fmt.Printf("dd_secret=%s\n", ddHex)
}

func cmdUninstall(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/config.yaml", "путь к конфигурации")
	purge := fs.Bool("purge", false, "удалить бинарник и конфиг")
	_ = fs.Parse(args)

	cfg, _, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("загрузка конфигурации", "err", err)
		os.Exit(1)
	}

	script := cfg.Management.UninstallScript
	if script == "" {
		script = "deploy/uninstall.sh"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := service.RunScript(ctx, script, *purge); err != nil {
		svcCfg := service.FromManagement(
			cfg.Management.ServiceName,
			cfg.Management.ServiceUnitPath,
			script,
			true,
		)
		slog.Error("удаление", "err", err)
		fmt.Println("Выполни вручную:", service.UninstallCommand(svcCfg))
		os.Exit(1)
	}
	fmt.Println("Сервис удалён")
}

func runServer(flags runFlags) {
	cfg, users, err := config.Load(flags.configPath)
	if err != nil {
		slog.Error("ошибка загрузки конфигурации", "err", err)
		os.Exit(1)
	}

	tracker := stats.New()
	rt := runtime.New(flags.configPath, cfg, users, tracker)

	names := make([]string, 0, len(users.Users()))
	for _, u := range users.Users() {
		names = append(names, u.Name)
	}

	var metricsSrv *metrics.Server
	if cfg.Metrics.Enabled() {
		metricsSrv = metrics.New(rt, cfg.Metrics)
	}

	slog.Info("PhantomProxy запущен",
		"version", version,
		"listen", cfg.Addr(),
		"users", names,
		"mask_host", users.MaskHost(),
		"fallback", cfg.Fallback.Upstream,
		"management", cfg.Management.Addr(),
		"metrics", metrics.FormatAddr(cfg.Metrics),
		"fronting", cfg.FrontingAction(),
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	proxySrv := proxy.New(rt, metricsSrv)
	adminSrv := admin.New(rt, cfg.Management, proxySrv)

	errCh := make(chan error, 3)
	go func() { errCh <- proxySrv.Serve(ctx) }()
	if cfg.Management.Enabled() {
		go func() { errCh <- adminSrv.Serve(ctx) }()
	}
	if metricsSrv != nil {
		go func() { errCh <- metricsSrv.Serve(ctx) }()
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
