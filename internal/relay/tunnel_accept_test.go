package relay

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestAcceptBackLegacyHandshake(t *testing.T) {
	psk := []byte("test-psk-32-bytes-long-enough!!")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan Meta, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _, meta, err := acceptBack(c, psk)
		if err != nil {
			t.Errorf("acceptBack: %v", err)
			return
		}
		done <- meta
	}()

	nonce := make([]byte, 16)
	copy(nonce, []byte("nonce-legacy-hs!"))
	mac := hmac.New(sha256.New, psk)
	mac.Write(nonce)
	tag := mac.Sum(nil)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	handshake := append([]byte("PHRP"), nonce...)
	handshake = append(handshake, tag...)
	var dcBuf [2]byte
	binary.BigEndian.PutUint16(dcBuf[:], uint16(int16(2)))
	handshake = append(handshake, dcBuf[:]...)
	if len(handshake) != handshakeBaseLen {
		t.Fatalf("len %d", len(handshake))
	}
	if _, err := conn.Write(handshake); err != nil {
		t.Fatal(err)
	}

	select {
	case meta := <-done:
		if meta.ClientIP != "0.0.0.0" && meta.ClientIP != "" {
			t.Errorf("client ip %q", meta.ClientIP)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}
