package middleproxy

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestDeriveKeysGolden(t *testing.T) {
	nonceSrv, _ := hex.DecodeString("9e23d004fe74bc7a604c74d9e9e003f4")
	nonceClt, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f10")
	cltTS, _ := hex.DecodeString("c29b756a")
	srvIP, _ := hex.DecodeString("90a19a95")
	cltPort, _ := hex.DecodeString("31d4")
	cltIP, _ := hex.DecodeString("7f000001")
	srvPort, _ := hex.DecodeString("b822")

	key, iv := deriveKeys(nonceSrv, nonceClt, cltTS, srvIP, cltPort, []byte("CLIENT"), cltIP, srvPort, DefaultProxySecret)
	wantKey, _ := hex.DecodeString("119d93cf06fce4ffdf85d8a223c4220f5fc390370b49d2b78fb3d27abbe98bb7")
	wantIV, _ := hex.DecodeString("8c2df4c0ebe767e0aee1a356ba0470bb")
	if !bytesEqual(key, wantKey) {
		t.Fatalf("key mismatch\ngot  %x\nwant %x", key, wantKey)
	}
	if !bytesEqual(iv, wantIV) {
		t.Fatalf("iv mismatch\ngot  %x\nwant %x", iv, wantIV)
	}
}

func TestBuildHandshakePayloadShape(t *testing.T) {
	p := buildHandshakePayload(0x7f000001, 54321, 0x959aa190, 8888)
	if len(p) != 32 {
		t.Fatalf("len %d", len(p))
	}
	if !bytesEqual(p[:4], rpcHandshakeTag) {
		t.Fatalf("tag %x", p[:4])
	}
	if got := binary.LittleEndian.Uint32(p[8:12]); got != 0x7f000001 {
		t.Fatalf("client ip %x", got)
	}
	if got := binary.LittleEndian.Uint16(p[12:14]); got != 54321 {
		t.Fatalf("client port %d", got)
	}
	if got := binary.LittleEndian.Uint32(p[20:24]); got != 0x959aa190 {
		t.Fatalf("server ip %x", got)
	}
	if got := binary.LittleEndian.Uint16(p[24:26]); got != 8888 {
		t.Fatalf("server port %d", got)
	}
}
