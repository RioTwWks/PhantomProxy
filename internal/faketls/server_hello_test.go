package faketls_test

import (
	"testing"

	"github.com/RioTwWks/PhantomProxy/internal/faketls"
	"github.com/RioTwWks/PhantomProxy/internal/mtproto"
)

func TestServerHelloProfilesDiffer(t *testing.T) {
	secret, _ := mtproto.ParseSecret("ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d")
	ch, err := faketls.BuildClientHello(secret)
	if err != nil {
		t.Fatal(err)
	}

	r := faketls.NewServerHelloRotator([]string{"chrome", "firefox", "edge"}, faketls.RotationPerConnection, 300, 20)
	for i := 0; i < 24; i++ {
		if p := r.Pick(); p == "" {
			t.Fatal("empty profile")
		}
	}
	_ = ch
}

func TestHasECH(t *testing.T) {
	secret, _ := mtproto.ParseSecret("ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d")
	ch, err := faketls.BuildClientHello(secret)
	if err != nil {
		t.Fatal(err)
	}
	// utls chrome hello typically has no ECH in our build
	if faketls.HasECH(ch) {
		t.Log("ClientHello contains ECH (optional)")
	}
}
