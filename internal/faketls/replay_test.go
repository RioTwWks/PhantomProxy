package faketls

import (
	"testing"
	"time"
)

func TestReplayCache(t *testing.T) {
	cache := NewReplayCache(100, time.Minute)
	ch := &ClientHello{}
	ch.Random[0] = 1

	if cache.Check(ch) {
		t.Fatal("первый ClientHello не должен быть replay")
	}
	if !cache.Check(ch) {
		t.Fatal("повторный ClientHello должен быть replay")
	}
	if cache.Hits() != 1 {
		t.Fatalf("hits=%d want 1", cache.Hits())
	}
}
