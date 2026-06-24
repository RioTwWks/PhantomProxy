package testdc

import (
	"testing"

	"github.com/RioTwWks/PhantomProxy/internal/obfuscated2"
)

func TestEncDecAlignment(t *testing.T) {
	header, enc, dec, err := obfuscated2.OutgoingHeader(2)
	if err != nil {
		t.Fatal(err)
	}

	mockDec := newCTR(copyBytes(header[8:40]), copyBytes(header[40:56]))
	advance := make([]byte, 64)
	mockDec.XORKeyStream(advance, advance)

	plain := []byte("test")
	cipher := make([]byte, len(plain))
	enc.XORKeyStream(cipher, plain)

	out := make([]byte, len(cipher))
	mockDec.XORKeyStream(out, cipher)

	if string(out) != string(plain) {
		t.Fatalf("proxy->mock: got %q want %q", out, plain)
	}

	mockEnc := newCTR(copyBytes(reverse(header)[8:40]), copyBytes(reverse(header)[40:56]))

	respCipher := make([]byte, len(plain))
	mockEnc.XORKeyStream(respCipher, plain)

	out2 := make([]byte, len(respCipher))
	dec.XORKeyStream(out2, respCipher)

	if string(out2) != string(plain) {
		t.Fatalf("mock->proxy: got %q want %q", out2, plain)
	}
}
