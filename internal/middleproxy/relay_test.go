package middleproxy

import (
	"testing"
)

func TestParseProxyAnsWireTag(t *testing.T) {
	frame := make([]byte, 20)
	copy(frame[:4], rpcProxyAns)
	copy(frame[16:], []byte("data"))

	data, err := parseProxyAns(frame)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "data" {
		t.Fatalf("data %q", data)
	}
}

func TestBuildProxyReqWireTag(t *testing.T) {
	id := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	msg := buildProxyReq([]byte{0, 0, 0, 0, 1, 2, 3, 4}, proxyConnOpts{
		ClientIP:   "185.210.143.32",
		ClientPort: 54942,
		LocalIP:    "212.192.215.248",
		LocalPort:  48164,
	}, id)
	if !bytesEqual(msg[:4], rpcProxyReq) {
		t.Fatalf("tag %x want %x", msg[:4], rpcProxyReq)
	}
}
