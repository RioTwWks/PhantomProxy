package probe_test

import (
	"testing"

	"github.com/RioTwWks/PhantomProxy/internal/probe"
)

func TestBlacklistBlocksAfterThreshold(t *testing.T) {
	bl := probe.NewBlacklist(3, 60, 600)
	if bl.IsBlocked("1.2.3.4") {
		t.Fatal("не должен быть заблокирован сразу")
	}
	for i := 0; i < 2; i++ {
		if bl.RecordProbe("1.2.3.4") {
			t.Fatalf("не должен блокировать на попытке %d", i+1)
		}
	}
	if !bl.RecordProbe("1.2.3.4") {
		t.Fatal("должен заблокировать на пороге")
	}
	if !bl.IsBlocked("1.2.3.4") {
		t.Fatal("IP должен быть в blacklist")
	}
}

func TestBlacklistDisabled(t *testing.T) {
	if probe.NewBlacklist(0, 60, 600) != nil {
		t.Fatal("threshold 0 = отключено")
	}
}
