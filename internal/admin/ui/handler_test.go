package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/RioTwWks/PhantomProxy/internal/config"
	"github.com/RioTwWks/PhantomProxy/internal/mtproto"
	"github.com/RioTwWks/PhantomProxy/internal/runtime"
	"github.com/RioTwWks/PhantomProxy/internal/stats"
	"github.com/RioTwWks/PhantomProxy/internal/user"
)

func TestUILoginAndDashboard(t *testing.T) {
	secret, _ := mtproto.ParseSecret("ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d")
	mgr, _ := user.NewManager([]user.User{{Name: "alice", Secret: secret, Enabled: true}}, nil, nil)
	cfg := config.Config{
		Listen:     config.ListenConfig{Host: "127.0.0.1", Port: 8443},
		Management: config.ManagementConfig{Token: "secret-token"},
	}
	rt := runtime.New("", cfg, mgr, stats.New())
	h := NewHandler(rt, config.ManagementConfig{Token: "secret-token"}, nil)

	mux := http.NewServeMux()
	h.Register(mux)

	// login page
	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/ui/login", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("login status = %d", resp.Code)
	}

	// submit login
	form := url.Values{"token": {"secret-token"}}
	req := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp = httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	if resp.Code != http.StatusSeeOther {
		t.Fatalf("login post status = %d", resp.Code)
	}
	cookie := resp.Result().Cookies()[0]

	// dashboard
	req = httptest.NewRequest(http.MethodGet, "/ui/", nil)
	req.AddCookie(cookie)
	resp = httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), "Дашборд") {
		t.Fatal("dashboard body missing title")
	}

	// partial stats
	req = httptest.NewRequest(http.MethodGet, "/ui/partials/stats", nil)
	req.AddCookie(cookie)
	resp = httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("stats partial status = %d", resp.Code)
	}
}

func TestUIRedirectRoot(t *testing.T) {
	secret, _ := mtproto.ParseSecret("ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d")
	mgr, _ := user.NewManager([]user.User{{Name: "alice", Secret: secret, Enabled: true}}, nil, nil)
	rt := runtime.New("", config.Config{}, mgr, stats.New())
	h := NewHandler(rt, config.ManagementConfig{}, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/", nil))
	if resp.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", resp.Code)
	}
}

func TestUIServiceUninstall(t *testing.T) {
	secret, _ := mtproto.ParseSecret("ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d")
	mgr, _ := user.NewManager([]user.User{{Name: "alice", Secret: secret, Enabled: true}}, nil, nil)
	cfg := config.Config{
		Listen: config.ListenConfig{Host: "127.0.0.1", Port: 8443},
		Management: config.ManagementConfig{
			Token:                 "secret-token",
			AllowServiceUninstall: true,
			ServiceName:           "phantom-proxy",
		},
	}
	rt := runtime.New("", cfg, mgr, stats.New())
	h := NewHandler(rt, cfg.Management, nil)

	mux := http.NewServeMux()
	h.Register(mux)

	form := url.Values{"token": {"secret-token"}}
	req := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	cookie := resp.Result().Cookies()[0]

	req = httptest.NewRequest(http.MethodGet, "/ui/settings", nil)
	req.AddCookie(cookie)
	resp = httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("settings status = %d", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), "Опасная зона") {
		t.Fatal("danger zone not shown")
	}
	if strings.Contains(resp.Body.String(), "Добавить пользователя") {
		t.Fatal("settings page shows users content")
	}

	badForm := url.Values{"confirm": {"delete"}}
	req = httptest.NewRequest(http.MethodPost, "/ui/service/uninstall", strings.NewReader(badForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp = httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	if resp.Code != http.StatusSeeOther {
		t.Fatalf("bad confirm status = %d", resp.Code)
	}
	if !strings.Contains(resp.Header().Get("Location"), "error=") {
		t.Fatal("expected error redirect")
	}
}
