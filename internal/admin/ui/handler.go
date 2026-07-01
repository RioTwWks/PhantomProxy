package ui

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/RioTwWks/PhantomProxy/internal/config"
	"github.com/RioTwWks/PhantomProxy/internal/mtproto"
	"github.com/RioTwWks/PhantomProxy/internal/runtime"
	"github.com/RioTwWks/PhantomProxy/internal/service"
	"github.com/RioTwWks/PhantomProxy/internal/user"
)

const sessionCookie = "phantom_session"

// Handler обслуживает WebUI.
type Handler struct {
	rt       *runtime.Runtime
	mgmt     config.ManagementConfig
	rebinder adminListenRebinder
	tmpl     *template.Template
}

type adminListenRebinder interface {
	RebindListenIfNeeded() (bool, error)
}

// NewHandler создаёт UI handler.
func NewHandler(rt *runtime.Runtime, mgmt config.ManagementConfig, rebinder adminListenRebinder) *Handler {
	var root *template.Template
	root = template.New("").Funcs(template.FuncMap{
		"formatBytes": formatBytes,
		"render": func(name string, data any) (template.HTML, error) {
			var buf bytes.Buffer
			if err := root.ExecuteTemplate(&buf, name, data); err != nil {
				return "", err
			}
			return template.HTML(buf.String()), nil
		},
	})
	root = template.Must(root.ParseFS(Templates(), "*.html", "partials/*.html"))
	return &Handler{rt: rt, mgmt: mgmt, rebinder: rebinder, tmpl: root}
}

// Register добавляет UI-маршруты на mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.Handle("/ui/static/", http.StripPrefix("/ui/static/", http.FileServer(http.FS(Static()))))

	mux.HandleFunc("/ui/login", h.handleLogin)
	mux.HandleFunc("/ui/", h.withSession(h.handleDashboard))
	mux.HandleFunc("/ui/users", h.withSession(h.handleUsers))
	mux.HandleFunc("/ui/users/", h.withSession(h.handleUserAction))
	mux.HandleFunc("/ui/settings", h.withSession(h.handleSettings))
	mux.HandleFunc("/ui/reload", h.withSession(h.handleReload))
	mux.HandleFunc("/ui/service/uninstall", h.withSession(h.handleServiceUninstall))
	mux.HandleFunc("/ui/partials/stats", h.withSession(h.handlePartialStats))
	mux.HandleFunc("/ui/partials/users-stats", h.withSession(h.handlePartialUsersStats))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/ui/", http.StatusSeeOther)
	})
}

func (h *Handler) withSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.mgmt.Token != "" && !h.hasSession(r) {
			http.Redirect(w, r, "/ui/login?next="+url.QueryEscape(r.URL.Path), http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func (h *Handler) hasSession(r *http.Request) bool {
	if h.mgmt.Token == "" {
		return true
	}
	c, err := r.Cookie(sessionCookie)
	return err == nil && c.Value == h.mgmt.Token
}

func (h *Handler) setSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    h.mgmt.Token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400 * 7,
	})
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if h.mgmt.Token == "" || h.hasSession(r) {
		http.Redirect(w, r, "/ui/", http.StatusSeeOther)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.render(w, "login.html", map[string]any{})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			h.render(w, "login.html", map[string]any{"Error": "некорректная форма"})
			return
		}
		if r.FormValue("token") != h.mgmt.Token {
			h.render(w, "login.html", map[string]any{"Error": "неверный токен"})
			return
		}
		h.setSession(w)
		next := r.FormValue("next")
		if next == "" {
			next = "/ui/"
		}
		http.Redirect(w, r, next, http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/ui/" && r.URL.Path != "/ui" {
		http.NotFound(w, r)
		return
	}
	h.render(w, "dashboard.html", h.dashboardData())
}

func (h *Handler) handlePartialStats(w http.ResponseWriter, r *http.Request) {
	h.render(w, "stats_cards", h.dashboardData())
}

func (h *Handler) handlePartialUsersStats(w http.ResponseWriter, r *http.Request) {
	h.render(w, "users_stats_table", h.dashboardData())
}

func (h *Handler) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.render(w, "users.html", h.usersPageData(r, ""))
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			h.render(w, "users.html", h.usersPageData(r, "некорректная форма"))
			return
		}
		if err := h.createUser(r); err != nil {
			h.render(w, "users.html", h.usersPageData(r, err.Error()))
			return
		}
		http.Redirect(w, r, "/ui/users?flash="+url.QueryEscape("Пользователь создан"), http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleUserAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/ui/users/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	name, action := parts[0], parts[1]

	var err error
	switch action {
	case "toggle":
		u, ok := h.findUser(name)
		if !ok {
			http.NotFound(w, r)
			return
		}
		enabled := !u.Enabled
		_, err = h.rt.Users.UpdateUser(name, nil, &enabled)
	case "delete":
		err = h.rt.Users.RemoveUser(name)
	default:
		http.NotFound(w, r)
		return
	}

	if err != nil {
		http.Redirect(w, r, "/ui/users?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	_ = h.rt.PersistUsers()
	http.Redirect(w, r, "/ui/users?flash="+url.QueryEscape("Изменения сохранены"), http.StatusSeeOther)
}

func (h *Handler) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.render(w, "settings.html", h.settingsPageData(r, ""))
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			h.render(w, "settings.html", h.settingsPageData(r, "некорректная форма"))
			return
		}
		if err := h.saveSettings(r); err != nil {
			h.render(w, "settings.html", h.settingsPageData(r, err.Error()))
			return
		}
		msg := "Настройки сохранены"
		if h.rebinder != nil {
			if rebound, err := h.rebinder.RebindListenIfNeeded(); err != nil {
				msg = "Сохранено, но rebind: " + err.Error()
			} else if rebound {
				msg = "Настройки сохранены, listen: " + h.rt.Snapshot().Addr()
			}
		}
		http.Redirect(w, r, "/ui/settings?flash="+url.QueryEscape(msg), http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := h.rt.Reload(); err != nil {
		http.Redirect(w, r, "/ui/settings?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	msg := "Конфигурация перезагружена"
	if h.rebinder != nil {
		if rebound, err := h.rebinder.RebindListenIfNeeded(); err != nil {
			msg = "Перезагружено, но rebind: " + err.Error()
		} else if rebound {
			msg = "Конфигурация перезагружена, listen: " + h.rt.Snapshot().Addr()
		}
	}
	http.Redirect(w, r, "/ui/settings?flash="+url.QueryEscape(msg), http.StatusSeeOther)
}

func (h *Handler) handleServiceUninstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.mgmt.AllowServiceUninstall {
		http.Redirect(w, r, "/ui/settings?error="+url.QueryEscape("Удаление сервиса отключено в конфигурации"), http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/ui/settings?error="+url.QueryEscape("некорректная форма"), http.StatusSeeOther)
		return
	}
	if err := service.ValidateConfirm(r.FormValue("confirm")); err != nil {
		http.Redirect(w, r, "/ui/settings?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	purge := r.FormValue("purge") == "on" || r.FormValue("purge") == "true"
	svcCfg := service.FromManagement(
		h.mgmt.ServiceName,
		h.mgmt.ServiceUnitPath,
		h.mgmt.UninstallScript,
		h.mgmt.AllowServiceUninstall,
	)
	result := service.ScheduleUninstall(svcCfg, purge)
	msg := result.Message
	if result.Command != "" {
		msg += ". Команда: " + result.Command
	}
	http.Redirect(w, r, "/ui/settings?flash="+url.QueryEscape(msg), http.StatusSeeOther)
}

func (h *Handler) createUser(r *http.Request) error {
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		return fmt.Errorf("имя обязательно")
	}

	secretText := strings.TrimSpace(r.FormValue("secret"))
	if secretText == "" {
		_, generated, err := user.GenerateSecret(strings.TrimSpace(r.FormValue("host")))
		if err != nil {
			return err
		}
		secretText = generated
	}

	secret, err := mtproto.ParseSecret(secretText)
	if err != nil {
		return err
	}

	if err := h.rt.Users.AddUser(user.User{Name: name, Secret: secret, Enabled: true}); err != nil {
		return err
	}
	return h.rt.PersistUsers()
}

func (h *Handler) saveSettings(r *http.Request) error {
	s := config.SettingsView{
		ListenHost:       r.FormValue("listen_host"),
		ListenPort:       atoi(r.FormValue("listen_port")),
		Backend:          r.FormValue("backend"),
		FallbackUpstream: r.FormValue("fallback_upstream"),
		RecordMinChunk:   atoi(r.FormValue("record_min_chunk")),
		RecordMaxChunk:   atoi(r.FormValue("record_max_chunk")),
		NoiseMean:        atoi(r.FormValue("noise_mean")),
		NoiseJitter:      atoi(r.FormValue("noise_jitter")),
		PublicServer:     r.FormValue("public_server"),
	}
	if ja3 := strings.TrimSpace(r.FormValue("allowed_ja3")); ja3 != "" {
		for _, part := range strings.Split(ja3, ",") {
			if v := strings.TrimSpace(part); v != "" {
				s.AllowedJA3 = append(s.AllowedJA3, v)
			}
		}
	}
	return h.rt.UpdateSettings(s)
}

func (h *Handler) dashboardData() map[string]any {
	cfg := h.rt.Snapshot()
	snap := h.rt.Stats.Snapshot()
	return map[string]any{
		"Title":         "Дашборд",
		"Active":        "dashboard",
		"PageContent":   "dashboard_content",
		"Stats":         snap,
		"UsersCount": len(h.rt.Users.Users()),
		"UptimeText": formatDuration(h.rt.Uptime()),
		"ListenAddr": cfg.Addr(),
		"MaskHost":   h.rt.Users.MaskHost(),
	}
}

func (h *Handler) usersPageData(r *http.Request, errMsg string) map[string]any {
	server, port := h.publicEndpoint()
	return map[string]any{
		"Title":       "Пользователи",
		"Active":      "users",
		"PageContent": "users_content",
		"Users":       h.rt.Users.ListViews(server, port),
		"Flash":  r.URL.Query().Get("flash"),
		"Error":  firstNonEmpty(errMsg, r.URL.Query().Get("error")),
	}
}

func (h *Handler) settingsPageData(r *http.Request, errMsg string) map[string]any {
	cfg := h.rt.Snapshot()
	settings := config.SettingsFromConfig(cfg)
	serviceName := h.mgmt.ServiceName
	if serviceName == "" {
		serviceName = "phantom-proxy"
	}
	return map[string]any{
		"Title":                 "Настройки",
		"Active":                "settings",
		"PageContent":           "settings_content",
		"Settings":              settings,
		"AllowedJA3Text":        strings.Join(settings.AllowedJA3, ", "),
		"AllowServiceUninstall": h.mgmt.AllowServiceUninstall,
		"ServiceName":           serviceName,
		"Flash":                 r.URL.Query().Get("flash"),
		"Error":                 firstNonEmpty(errMsg, r.URL.Query().Get("error")),
	}
}

func (h *Handler) publicEndpoint() (string, int) {
	cfg := h.rt.Snapshot()
	server := cfg.Management.PublicServer
	if server == "" {
		server = cfg.Listen.Host
		if server == "" || server == "0.0.0.0" {
			server = "127.0.0.1"
		}
	}
	return server, cfg.Listen.Port
}

func (h *Handler) findUser(name string) (user.User, bool) {
	for _, u := range h.rt.Users.Users() {
		if u.Name == name {
			return u, true
		}
	}
	return user.User{}, false
}

func (h *Handler) render(w http.ResponseWriter, name string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for cur := n / unit; cur >= unit; cur /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dч %02dм", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dм %02dс", m, s)
	}
	return fmt.Sprintf("%dс", s)
}

func atoi(v string) int {
	n, _ := strconv.Atoi(v)
	return n
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
