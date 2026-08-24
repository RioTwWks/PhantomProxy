package middleproxy

import (
	"testing"
)

func TestParseAdTag(t *testing.T) {
	tag, err := ParseAdTag("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if len(tag) != 16 {
		t.Fatalf("len=%d", len(tag))
	}
	if _, err := ParseAdTag("short"); err == nil {
		t.Fatal("ожидалась ошибка")
	}
	if tag, err := ParseAdTag(""); err != nil || tag != nil {
		t.Fatalf("empty: tag=%v err=%v", tag, err)
	}
}

func TestResolveEndpoints(t *testing.T) {
	eps := ResolveEndpoints(2)
	if len(eps) == 0 {
		t.Fatal("нет endpoints для DC2")
	}
	media := ResolveEndpoints(-2)
	if len(media) == 0 {
		t.Fatal("нет endpoints для MEDIA DC2")
	}
	if ResolveEndpoints(65534) != nil {
		t.Fatal("65534 не должен резолвиться как middle proxy DC")
	}
}

func TestCRC32(t *testing.T) {
	if crc32IEEE([]byte("test")) == 0 {
		t.Fatal("crc=0")
	}
}
