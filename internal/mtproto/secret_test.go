package mtproto

import "testing"

func TestParseSecretHex(t *testing.T) {
	t.Parallel()

	const raw = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
	s, err := ParseSecret(raw)
	if err != nil {
		t.Fatalf("ParseSecret: %v", err)
	}

	wantKey := "367a189aee18fa31c190054efd4a8e95"
	gotKey := hexEncode(s.Key[:])
	if gotKey != wantKey {
		t.Fatalf("key = %s, want %s", gotKey, wantKey)
	}
	if s.Host != "storage.googleapis.com" {
		t.Fatalf("host = %q, want storage.googleapis.com", s.Host)
	}
}

func TestParseSecretSecure(t *testing.T) {
	t.Parallel()

	const raw = "dd0123456789abcdef0123456789abcdef"
	s, err := ParseSecret(raw)
	if err != nil {
		t.Fatalf("ParseSecret dd: %v", err)
	}
	if !s.IsSecure() {
		t.Fatal("ожидался dd-секрет")
	}
	if s.Host != "" {
		t.Fatalf("dd host должен быть пустым, got %q", s.Host)
	}
}

func TestParseSecretRejectsInvalidPrefix(t *testing.T) {
	t.Parallel()

	_, err := ParseSecret("aa0123456789abcdef0123456789abcdef6578616d706c652e636f6d")
	if err == nil {
		t.Fatal("ожидалась ошибка для неверного префикса")
	}
}

func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out)
}
