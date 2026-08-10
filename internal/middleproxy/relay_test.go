package middleproxy

import (
	"bytes"
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

func TestProxyConnWriteRejectsUnaligned(t *testing.T) {
	pc := &proxyConn{relay: &relayConn{}}
	if _, err := pc.Write([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for unaligned payload")
	}
}

func TestProxyConnWriteAlignedChunk(t *testing.T) {
	payload := make([]byte, 40)
	var plain bytes.Buffer
	pc := &proxyConn{
		relay: &relayConn{},
		opts: proxyConnOpts{
			ClientIP:   "185.210.143.32",
			ClientPort: 10300,
			LocalIP:    "212.192.215.248",
			LocalPort:  55924,
		},
	}
	pc.connID = [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	msg := buildProxyReq(payload, pc.opts, pc.connID[:])
	if err := writeFrame(&plain, 0, msg); err != nil {
		t.Fatal(err)
	}
}

func TestIndependentReadWriteSeq(t *testing.T) {
	// После handshake readSeq=0, writeSeq=0. Запись инкрементирует только writeSeq.
	writeSeq := int32(0)
	readSeq := int32(0)

	var reqBuf bytes.Buffer
	if err := writeFrame(&reqBuf, writeSeq, []byte{1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	writeSeq++
	if writeSeq != 1 || readSeq != 0 {
		t.Fatalf("after write: read=%d write=%d", readSeq, writeSeq)
	}

	ans := make([]byte, 20)
	copy(ans[:4], rpcProxyAns)
	copy(ans[16:], []byte("ok"))
	var ansBuf bytes.Buffer
	if err := writeFrame(&ansBuf, 0, ans); err != nil {
		t.Fatal(err)
	}

	got, err := readFrame(&ansBuf, &readSeq)
	if err != nil {
		t.Fatalf("read at seq 0 failed: %v", err)
	}
	if string(got[16:18]) != "ok" {
		t.Fatalf("payload %q", got[16:])
	}
}
