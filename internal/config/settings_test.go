package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/RioTwWks/PhantomProxy/internal/mtproto"
	"github.com/RioTwWks/PhantomProxy/internal/user"
)

func TestSaveAndApplySettings(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	secret, _ := mtproto.ParseSecret("ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d")
	enabled := true
	cfg := Config{
		Listen: ListenConfig{Host: "127.0.0.1", Port: 8443},
		MTProto: MTProtoConfig{
			Users: []UserConfig{{
				Name: "alice", Secret: mtproto.EncodeHex(secret), Enabled: &enabled,
			}},
		},
		TLS: TLSConfig{RecordMinChunk: 512, RecordMaxChunk: 4096},
		Management: ManagementConfig{Host: "127.0.0.1", Port: 8081, Token: "t"},
	}

	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}

	updated := ApplySettings(cfg, SettingsView{
		ListenHost:       "0.0.0.0",
		ListenPort:       9443,
		FallbackUpstream: "http://127.0.0.1:9090",
		RecordMinChunk:   256,
		RecordMaxChunk:   2048,
		PublicServer:     "203.0.113.10",
	})
	updated.MTProto.Users = UsersToConfig([]user.User{{Name: "alice", Secret: secret, Enabled: true}})

	if err := Save(path, updated); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("пустой config")
	}

	loaded, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Listen.Port != 9443 {
		t.Fatalf("port = %d", loaded.Listen.Port)
	}
	if loaded.Management.PublicServer != "203.0.113.10" {
		t.Fatalf("public_server = %q", loaded.Management.PublicServer)
	}
}
