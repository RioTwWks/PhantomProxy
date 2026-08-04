package faketls_test

import (
	"testing"

	"github.com/RioTwWks/PhantomProxy/internal/faketls"
	utls "github.com/refraction-networking/utls"
)

func TestParseFingerprintPool(t *testing.T) {
	ids, names, err := faketls.ParseFingerprintPool([]string{"chrome_auto", "firefox_120"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || len(names) != 2 {
		t.Fatalf("pool len = %d/%d", len(ids), len(names))
	}
	if ids[0] != utls.HelloChrome_Auto {
		t.Fatalf("first id = %+v", ids[0])
	}
}

func TestFingerprintRotatorPerConnection(t *testing.T) {
	r, err := faketls.NewFingerprintRotator([]string{"chrome_auto", "firefox_auto"}, faketls.RotationPerConnection, 300, 20)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[utls.ClientHelloID]struct{})
	for i := 0; i < 32; i++ {
		seen[r.Pick()] = struct{}{}
	}
	if len(seen) < 2 {
		t.Fatalf("ожидалась вариативность отпечатков, got %d", len(seen))
	}
}

func TestFingerprintRotatorAdaptive(t *testing.T) {
	r, err := faketls.NewFingerprintRotator([]string{"chrome_auto", "firefox_auto"}, faketls.RotationAdaptive, 300, 3)
	if err != nil {
		t.Fatal(err)
	}
	before := r.CurrentName()
	for i := 0; i < 3; i++ {
		r.RecordFailure()
	}
	after := r.CurrentName()
	if before == after {
		t.Fatalf("adaptive не сменил отпечаток: %q -> %q", before, after)
	}
}

func TestSNIRotator(t *testing.T) {
	r := faketls.NewSNIRotator([]string{"a.example", "b.example"}, faketls.RotationPerConnection, 300)
	if r.Pick("fallback") == "fallback" {
		t.Fatal("ожидался SNI из пула")
	}
	if faketls.NewSNIRotator(nil, "", 0) != nil {
		t.Fatal("пустой пул должен давать nil")
	}
}
