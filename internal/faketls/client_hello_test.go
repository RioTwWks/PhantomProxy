package faketls

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"
)

func TestValidateClientHelloRoundTrip(t *testing.T) {
	t.Parallel()

	secret := []byte{
		0x36, 0x7a, 0x18, 0x9a, 0xee, 0x18, 0xfa, 0x31,
		0xc1, 0x90, 0x05, 0x4e, 0xfd, 0x4a, 0x8e, 0x9,
	}

	ch := buildTestClientHello(t, secret)
	if err := validateClientHello(ch, secret); err != nil {
		t.Fatalf("validateClientHello: %v", err)
	}
}

func TestValidateClientHelloRejectsWrongSecret(t *testing.T) {
	t.Parallel()

	secret := []byte{
		0x36, 0x7a, 0x18, 0x9a, 0xee, 0x18, 0xfa, 0x31,
		0xc1, 0x90, 0x05, 0x4e, 0xfd, 0x4a, 0x8e, 0x9,
	}
	wrong := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}

	ch := buildTestClientHello(t, secret)
	if err := validateClientHello(ch, wrong); err == nil {
		t.Fatal("ожидалась ошибка для неверного секрета")
	}
}

func buildTestClientHello(t *testing.T, secret []byte) *ClientHello {
	t.Helper()

	// Минимальный ClientHello с SNI storage.googleapis.com
	sni := []byte{
		0x00, 0x00, // server_name
		0x00, 0x17,
		0x00, 0x15,
		0x00,
	}
	sni = append(sni, []byte("storage.googleapis.com")...)

	var hello []byte
	hello = append(hello, 0x01) // ClientHello
	hello = append(hello, 0, 0, 0) // length placeholder
	hello = append(hello, 0x03, 0x03) // TLS 1.2

	random := make([]byte, 32)
	hello = append(hello, random...)
	hello = append(hello, 0x00) // empty session id
	hello = append(hello, 0x00, 0x02, 0x13, 0x01) // one cipher
	hello = append(hello, 0x01, 0x00) // compression

	extLen := len(sni)
	hello = append(hello, byte(extLen>>8), byte(extLen))
	hello = append(hello, sni...)

	bodyLen := len(hello) - 4
	hello[1] = byte(bodyLen >> 16)
	hello[2] = byte(bodyLen >> 8)
	hello[3] = byte(bodyLen)

	record := make([]byte, 0, 5+len(hello))
	record = append(record, recordHandshake, 0x03, 0x01)
	record = append(record, byte(len(hello)>>8), byte(len(hello)))
	record = append(record, hello...)

	for i := 0; i < 32; i++ {
		record[randomOffset+i] = 0
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(record)
	digest := mac.Sum(nil)

	ts := uint32(time.Now().Unix())
	binary.LittleEndian.PutUint32(digest[28:], binary.LittleEndian.Uint32(digest[28:])^ts)
	for i := 0; i < 32; i++ {
		record[randomOffset+i] = digest[i]
	}

	var chRandom [32]byte
	copy(chRandom[:], record[randomOffset:randomOffset+32])

	return &ClientHello{
		Raw:    record,
		Random: chRandom,
	}
}

func TestIsHandshakeRecord(t *testing.T) {
	t.Parallel()
	if !IsHandshakeRecord(recordHandshake) {
		t.Fatal("ожидался TLS handshake")
	}
	if IsHandshakeRecord(0x17) {
		t.Fatal("application data не должен считаться handshake")
	}
}

func TestParseSNIFromExtensions(t *testing.T) {
	t.Parallel()

	name := []byte("example.com")
	extData := make([]byte, 0, 2+1+2+len(name))
	extData = append(extData, 0, byte(1+2+len(name)))
	extData = append(extData, 0)
	extData = append(extData, byte(len(name)>>8), byte(len(name)))
	extData = append(extData, name...)

	ext := make([]byte, 0, 4+len(extData))
	ext = append(ext, 0, 0)
	ext = append(ext, byte(len(extData)>>8), byte(len(extData)))
	ext = append(ext, extData...)

	if got := parseSNI(ext); got != "example.com" {
		t.Fatalf("parseSNI = %q", got)
	}
}
