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
}

func TestCRC32(t *testing.T) {
	if crc32IEEE([]byte("test")) == 0 {
		t.Fatal("crc=0")
	}
}
