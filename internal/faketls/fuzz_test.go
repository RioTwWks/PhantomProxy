package faketls

import (
	"bytes"
	"testing"
)

func FuzzParseClientHello(f *testing.F) {
	// минимальный TLS record header
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			return
		}
		_, _ = ParseClientHello(bytes.NewReader(data))
	})
}

func FuzzIsHandshakeRecord(f *testing.F) {
	f.Add(byte(0x16))
	f.Add(byte(0x00))
	f.Fuzz(func(t *testing.T, b byte) {
		_ = IsHandshakeRecord(b)
	})
}
