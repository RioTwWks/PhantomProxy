package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/RioTwWks/PhantomProxy/internal/config"
	"github.com/RioTwWks/PhantomProxy/internal/mtproto"
	"github.com/RioTwWks/PhantomProxy/internal/runtime"
	"github.com/RioTwWks/PhantomProxy/internal/stats"
	"github.com/RioTwWks/PhantomProxy/internal/user"
)

func TestAdminAPIUsersAndStats(t *testing.T) {
	secret, err := mtproto.ParseSecret("ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d")
	if err != nil {
		t.Fatal(err)
	}

	mgr, err := user.NewManager([]user.User{{Name: "alice", Secret: secret, Enabled: true}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{
		Listen: config.ListenConfig{Host: "127.0.0.1", Port: 8443},
		Management: config.ManagementConfig{
			Host:  "127.0.0.1",
			Port:  18081,
			Token: "test-token",
		},
	}
	rt := runtime.New("", cfg, mgr, stats.New())
	rt.Stats.OnConnect("alice")
	rt.Stats.AddTraffic("alice", 10, 20)

	srv := New(rt, cfg.Management)
	ts := httptest.NewServer(srv.server.Handler)
	defer ts.Close()

	t.Run("health", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/api/v1/health")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode)
		}
	})

	t.Run("status", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/status", nil)
		req.Header.Set("Authorization", "Bearer test-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode)
		}
	})

	t.Run("users", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/users?server=1.2.3.4&port=443", nil)
		req.Header.Set("Authorization", "Bearer test-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode)
		}
	})

	t.Run("create_user", func(t *testing.T) {
		body := bytes.NewBufferString(`{"name":"carol","host":"example.com"}`)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/users", body)
		req.Header.Set("Authorization", "Bearer test-token")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("status = %d", resp.StatusCode)
		}
	})

	t.Run("stats", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/stats/alice", nil)
		req.Header.Set("Authorization", "Bearer test-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		var stat struct {
			UploadBytes int64 `json:"upload_bytes"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&stat); err != nil {
			t.Fatal(err)
		}
		if stat.UploadBytes != 10 {
			t.Fatalf("upload = %d", stat.UploadBytes)
		}
	})

	t.Run("unauthorized", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/api/v1/status")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d", resp.StatusCode)
		}
	})

	t.Run("service_uninstall_disabled", func(t *testing.T) {
		body := bytes.NewBufferString(`{"confirm":"УДАЛИТЬ","purge":false}`)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/service/uninstall", body)
		req.Header.Set("Authorization", "Bearer test-token")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d", resp.StatusCode)
		}
	})
}

func TestAdminAPIServiceUninstallEnabled(t *testing.T) {
	secret, err := mtproto.ParseSecret("ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d")
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := user.NewManager([]user.User{{Name: "alice", Secret: secret, Enabled: true}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	mgmt := config.ManagementConfig{
		Host:                  "127.0.0.1",
		Port:                  18082,
		Token:                 "test-token",
		AllowServiceUninstall: true,
		ServiceName:           "phantom-proxy",
	}
	rt := runtime.New("", config.Config{Management: mgmt}, mgr, stats.New())
	srv := New(rt, mgmt)
	ts := httptest.NewServer(srv.server.Handler)
	defer ts.Close()

	t.Run("bad_confirm", func(t *testing.T) {
		body := bytes.NewBufferString(`{"confirm":"delete","purge":false}`)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/service/uninstall", body)
		req.Header.Set("Authorization", "Bearer test-token")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d", resp.StatusCode)
		}
	})

	t.Run("ok", func(t *testing.T) {
		body := bytes.NewBufferString(`{"confirm":"УДАЛИТЬ","purge":false}`)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/service/uninstall", body)
		req.Header.Set("Authorization", "Bearer test-token")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		var result struct {
			Scheduled bool   `json:"scheduled"`
			Message   string `json:"message"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		if result.Message == "" {
			t.Fatal("empty message")
		}
	})
}
