package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	// ConfirmPhrase — фраза подтверждения для удаления через UI/API.
	ConfirmPhrase = "УДАЛИТЬ"
)

// Config — параметры systemd-сервиса.
type Config struct {
	Name        string
	UnitPath    string
	ScriptPath  string
	AllowUninst bool
}

// Result — итог попытки удаления.
type Result struct {
	Scheduled bool   `json:"scheduled"`
	Message   string `json:"message"`
	Command   string `json:"command,omitempty"`
}

// FromManagement собирает Config из management-настроек.
func FromManagement(name, unitPath, scriptPath string, allow bool) Config {
	if name == "" {
		name = "phantom-proxy"
	}
	if unitPath == "" {
		unitPath = filepath.Join("/etc/systemd/system", name+".service")
	}
	return Config{
		Name:        name,
		UnitPath:    unitPath,
		ScriptPath:  scriptPath,
		AllowUninst: allow,
	}
}

// ValidateConfirm проверяет фразу подтверждения.
func ValidateConfirm(got string) error {
	if got != ConfirmPhrase {
		return fmt.Errorf("нужно ввести %q для подтверждения", ConfirmPhrase)
	}
	return nil
}

// Uninstall останавливает и отключает systemd unit. При purge и root — удаляет unit и каталоги.
func Uninstall(ctx context.Context, cfg Config, purge bool) error {
	if !cfg.AllowUninst {
		return errors.New("удаление сервиса отключено в конфигурации")
	}
	if cfg.Name == "" {
		return errors.New("service_name не задан")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("systemctl не найден")
	}

	if err := runSystemctl(ctx, "stop", cfg.Name); err != nil {
		return fmt.Errorf("systemctl stop: %w", err)
	}
	if err := runSystemctl(ctx, "disable", cfg.Name); err != nil {
		return fmt.Errorf("systemctl disable: %w", err)
	}
	if purge {
		if os.Getuid() != 0 {
			return errors.New("purge требует root")
		}
		_ = os.Remove(cfg.UnitPath)
		_ = runSystemctl(ctx, "daemon-reload")
		_ = os.RemoveAll("/opt/phantomproxy")
		_ = os.RemoveAll("/etc/phantomproxy")
	}
	return nil
}

// ScheduleUninstall запускает удаление в фоне (HTTP-ответ уходит до остановки процесса).
func ScheduleUninstall(cfg Config, purge bool) Result {
	if !cfg.AllowUninst {
		return Result{
			Message: "Удаление отключено. Задайте management.allow_service_uninstall: true",
			Command: UninstallCommand(cfg),
		}
	}

	if _, err := exec.LookPath("systemctl"); err != nil {
		return Result{
			Message: "systemctl недоступен — выполни команду вручную",
			Command: UninstallCommand(cfg),
		}
	}

	go func() {
		time.Sleep(2 * time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = Uninstall(ctx, cfg, purge)
	}()

	return Result{
		Scheduled: true,
		Message:   fmt.Sprintf("Сервис %q будет остановлен через несколько секунд", cfg.Name),
	}
}

// RunScript запускает deploy/uninstall.sh.
func RunScript(ctx context.Context, scriptPath string, purge bool) error {
	if scriptPath == "" {
		return errors.New("путь к скрипту не задан")
	}
	if _, err := os.Stat(scriptPath); err != nil {
		return fmt.Errorf("скрипт %s: %w", scriptPath, err)
	}
	args := []string{scriptPath}
	if purge {
		args = append(args, "--purge")
	}
	cmd := exec.CommandContext(ctx, "/bin/bash", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// UninstallCommand возвращает команду для ручного удаления.
func UninstallCommand(cfg Config) string {
	if cfg.ScriptPath != "" {
		return fmt.Sprintf("sudo bash %s", cfg.ScriptPath)
	}
	return fmt.Sprintf("sudo systemctl stop %s && sudo systemctl disable %s", cfg.Name, cfg.Name)
}

func runSystemctl(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
