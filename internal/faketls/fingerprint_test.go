package faketls

import (
	"testing"

	"github.com/RioTwWks/PhantomProxy/internal/mtproto"
)

func TestJA3StableForSameHello(t *testing.T) {
	t.Parallel()

	secret, err := mtproto.ParseSecret("ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d")
	if err != nil {
		t.Fatal(err)
	}

	ch, err := BuildClientHello(secret)
	if err != nil {
		t.Fatal(err)
	}

	ja3a := JA3(ch.Raw)
	ja3b := JA3(ch.Raw)
	if ja3a != ja3b {
		t.Fatalf("JA3 нестабилен: %s vs %s", ja3a, ja3b)
	}
	if len(ja3a) != 32 {
		t.Fatalf("JA3 len = %d", len(ja3a))
	}
}

func TestJA4NotEmpty(t *testing.T) {
	t.Parallel()

	secret, err := mtproto.ParseSecret("ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d")
	if err != nil {
		t.Fatal(err)
	}
	ch, err := BuildClientHello(secret)
	if err != nil {
		t.Fatal(err)
	}
	if JA4(ch.Raw) == "" {
		t.Fatal("JA4 пуст")
	}
}

func TestRecordPolicyChunkSize(t *testing.T) {
	t.Parallel()

	p := RecordPolicy{MinChunk: 100, MaxChunk: 200}.Normalize()
	for range 50 {
		size := p.chunkSize(500)
		if size < 100 || size > 200 {
			t.Fatalf("chunk = %d, want 100..200", size)
		}
	}
	if p.chunkSize(50) != 50 {
		t.Fatal("маленький буфер должен отдаваться целиком")
	}
}
