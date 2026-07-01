package admin

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/RioTwWks/PhantomProxy/internal/admin/ui"
	"github.com/RioTwWks/PhantomProxy/internal/config"
	"github.com/RioTwWks/PhantomProxy/internal/mtproto"
	"github.com/RioTwWks/PhantomProxy/internal/runtime"
	"github.com/RioTwWks/PhantomProxy/internal/service"
	"github.com/RioTwWks/PhantomProxy/internal/user"
)

// ListenRebinder перепривязывает TCP-listener прокси при смене порта.
type ListenRebinder interface {
	RebindListenIfNeeded() (bool, error)
}

// Server — HTTP API управления PhantomProxy.
type Server struct {
	rt       *runtime.Runtime
	mgmt     config.ManagementConfig
	rebinder ListenRebinder
	server   *http.Server
}

// New создаёт сервер управления.
func New(rt *runtime.Runtime, cfg config.ManagementConfig, rebinder ListenRebinder) *Server {
	s := &Server{rt: rt, mgmt: cfg, rebinder: rebinder}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", s.handleHealth)
	mux.HandleFunc("/api/v1/status", s.withAuth(s.handleStatus))
	mux.HandleFunc("/api/v1/users", s.withAuth(s.handleUsers))
	mux.HandleFunc("/api/v1/users/", s.withAuth(s.handleUserByName))
	mux.HandleFunc("/api/v1/stats", s.withAuth(s.handleStats))
	mux.HandleFunc("/api/v1/stats/", s.withAuth(s.handleStatsByName))
	mux.HandleFunc("/api/v1/reload", s.withAuth(s.handleReload))
	mux.HandleFunc("/api/v1/config", s.withAuth(s.handleConfig))
	mux.HandleFunc("/api/v1/service/uninstall", s.withAuth(s.handleServiceUninstall))

	ui.NewHandler(s.rt, cfg, rebinder).Register(mux)

	s.server = &http.Server{
		Addr:              cfg.Addr(),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s
}

// Serve запускает HTTP API.
func (s *Server) Serve(ctx context.Context) error {
	slog.Info("API управления слушает", "addr", s.server.Addr)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.server.Shutdown(shutdownCtx)
	}()
	err := s.server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.mgmt.Token != "" && !checkToken(r, s.mgmt.Token) {
			writeError(w, http.StatusUnauthorized, "неверный токен")
			return
		}
		next(w, r)
	}
}

func checkToken(r *http.Request, token string) bool {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ") == token
	}
	return r.Header.Get("X-API-Token") == token
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	cfg := s.rt.Snapshot()
	snap := s.rt.Stats.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"uptime_seconds":     int64(s.rt.Uptime().Seconds()),
		"listen_addr":        cfg.Addr(),
		"mask_host":          s.rt.Users.MaskHost(),
		"backend":            cfg.MTProto.Backend,
		"users_count":        len(s.rt.Users.Users()),
		"active_connections": snap.ActiveConnections,
		"total_connections":  snap.TotalConnections,
		"upload_bytes":       snap.UploadBytes,
		"download_bytes":     snap.DownloadBytes,
	})
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listUsers(w, r)
	case http.MethodPost:
		s.createUser(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "метод не поддерживается")
	}
}

func (s *Server) handleUserByName(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	if name == "" || strings.Contains(name, "/") {
		writeError(w, http.StatusNotFound, "пользователь не найден")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getUser(w, r, name)
	case http.MethodPut:
		s.updateUser(w, r, name)
	case http.MethodDelete:
		s.deleteUser(w, r, name)
	default:
		writeError(w, http.StatusMethodNotAllowed, "метод не поддерживается")
	}
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	server, port := s.proxyEndpoint(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"users": s.rt.Users.ListViews(server, port),
	})
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request, name string) {
	server, port := s.proxyEndpoint(r)
	view, ok := s.rt.Users.GetView(name, server, port)
	if !ok {
		writeError(w, http.StatusNotFound, "пользователь не найден")
		return
	}
	writeJSON(w, http.StatusOK, view)
}

type createUserRequest struct {
	Name    string `json:"name"`
	Secret  string `json:"secret"`
	Host    string `json:"host"`
	Enabled *bool  `json:"enabled"`
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name обязателен")
		return
	}

	secretText := req.Secret
	if secretText == "" {
		_, generated, err := user.GenerateSecret(req.Host)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		secretText = generated
	}

	secret, err := mtproto.ParseSecret(secretText)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	u := user.User{Name: req.Name, Secret: secret, Enabled: enabled}
	if err := s.rt.Users.AddUser(u); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err := s.rt.PersistUsers(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	server, port := s.proxyEndpoint(r)
	view, _ := s.rt.Users.GetView(req.Name, server, port)
	writeJSON(w, http.StatusCreated, view)
}

type updateUserRequest struct {
	Secret  string `json:"secret"`
	Enabled *bool  `json:"enabled"`
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request, name string) {
	var req updateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}

	var secret *mtproto.Secret
	if req.Secret != "" {
		parsed, err := mtproto.ParseSecret(req.Secret)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		secret = &parsed
	}

	updated, err := s.rt.Users.UpdateUser(name, secret, req.Enabled)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if err := s.rt.PersistUsers(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	server, port := s.proxyEndpoint(r)
	view, _ := s.rt.Users.GetView(updated.Name, server, port)
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) deleteUser(w http.ResponseWriter, _ *http.Request, name string) {
	if err := s.rt.Users.RemoveUser(name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.rt.PersistUsers(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "метод не поддерживается")
		return
	}
	writeJSON(w, http.StatusOK, s.rt.Stats.Snapshot())
}

func (s *Server) handleStatsByName(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "метод не поддерживается")
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/stats/")
	if name == "" {
		s.handleStats(w, r)
		return
	}
	stat, ok := s.rt.Stats.User(name)
	if !ok {
		writeError(w, http.StatusNotFound, "статистика не найдена")
		return
	}
	writeJSON(w, http.StatusOK, stat)
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "метод не поддерживается")
		return
	}
	if err := s.rt.Reload(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.reloadResponse())
}

func (s *Server) reloadResponse() map[string]any {
	resp := map[string]any{"status": "reloaded"}
	if s.rebinder != nil {
		rebound, err := s.rebinder.RebindListenIfNeeded()
		if err != nil {
			resp["listen_rebind_error"] = err.Error()
		} else if rebound {
			resp["listen_rebound"] = true
			resp["listen_addr"] = s.rt.Snapshot().Addr()
		}
	}
	return resp
}

func (s *Server) applyConfigResponse(settings config.SettingsView) (map[string]any, error) {
	if err := s.rt.UpdateSettings(settings); err != nil {
		return nil, err
	}
	resp := map[string]any{"settings": config.SettingsFromConfig(s.rt.Snapshot())}
	if s.rebinder != nil {
		rebound, err := s.rebinder.RebindListenIfNeeded()
		if err != nil {
			resp["listen_rebind_error"] = err.Error()
		} else if rebound {
			resp["listen_rebound"] = true
			resp["listen_addr"] = s.rt.Snapshot().Addr()
		}
	}
	return resp, nil
}

type uninstallRequest struct {
	Confirm string `json:"confirm"`
	Purge   bool   `json:"purge"`
}

func (s *Server) handleServiceUninstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "метод не поддерживается")
		return
	}
	if !s.mgmt.AllowServiceUninstall {
		writeError(w, http.StatusForbidden, "удаление сервиса отключено в конфигурации")
		return
	}

	var req uninstallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
		return
	}
	if err := service.ValidateConfirm(req.Confirm); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	svcCfg := service.FromManagement(
		s.mgmt.ServiceName,
		s.mgmt.ServiceUnitPath,
		s.mgmt.UninstallScript,
		s.mgmt.AllowServiceUninstall,
	)
	result := service.ScheduleUninstall(svcCfg, req.Purge)
	status := http.StatusAccepted
	if !result.Scheduled {
		status = http.StatusOK
	}
	writeJSON(w, status, result)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, config.SettingsFromConfig(s.rt.Snapshot()))
	case http.MethodPut:
		var settings config.SettingsView
		if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
			writeError(w, http.StatusBadRequest, "некорректный JSON")
			return
		}
		resp, err := s.applyConfigResponse(settings)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)
	default:
		writeError(w, http.StatusMethodNotAllowed, "метод не поддерживается")
	}
}

func (s *Server) proxyEndpoint(r *http.Request) (string, int) {
	if server := r.URL.Query().Get("server"); server != "" {
		port := s.rt.Snapshot().Listen.Port
		if p := r.URL.Query().Get("port"); p != "" {
			if v, err := strconv.Atoi(p); err == nil {
				port = v
			}
		}
		return server, port
	}

	cfg := s.rt.Snapshot()
	server := cfg.Management.PublicServer
	if server == "" {
		server = cfg.Listen.Host
		if server == "" || server == "0.0.0.0" {
			server = "127.0.0.1"
		}
	}
	return server, cfg.Listen.Port
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
