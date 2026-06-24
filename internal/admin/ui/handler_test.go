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
	mgr, _ := user.NewManager([]user.User{{Name: "alice", Secret: secret, Enabled: true}}, nil)
	cfg := config.Config{
		Listen:     config.ListenConfig{Host: "127.0.0.1", Port: 8443},
		Management: config.ManagementConfig{Token: "secret-token"},
	}
	rt := runtime.New("", cfg, mgr, stats.New())
	h := NewHandler(rt, "secret-token")

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
	mgr, _ := user.NewManager([]user.User{{Name: "alice", Secret: secret, Enabled: true}}, nil)
	rt := runtime.New("", config.Config{}, mgr, stats.New())
	h := NewHandler(rt, "")
	mux := http.NewServeMux()
	h.Register(mux)

	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/", nil))
	if resp.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", resp.Code)
	}
}
