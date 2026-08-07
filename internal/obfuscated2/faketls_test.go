package obfuscated2

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestFakeTLSObfuscated2RoundTrip(t *testing.T) {
	secret := []byte("40197aeb7c14b99661503f76fce2ca")

	clientLn, serverLn := net.Pipe()
	t.Cleanup(func() {
		_ = clientLn.Close()
		_ = serverLn.Close()
	})

	header, enc, dec, err := ClientStreamsForFakeTLS(2, secret)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		if _, err := clientLn.Write(header); err != nil {
			t.Errorf("client write header: %v", err)
		}
		payload := []byte("ping")
		buf := make([]byte, len(payload))
		enc.XORKeyStream(buf, payload)
		if _, err := clientLn.Write(buf); err != nil {
			t.Errorf("client write payload: %v", err)
		}
	}()

	obfConn, dcID, err := Handshake(serverLn, serverLn, secret)
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	if dcID != 2 {
		t.Fatalf("dcID=%d want 2", dcID)
	}

	got := make([]byte, 4)
	if _, err := io.ReadFull(obfConn, got); err != nil {
		t.Fatal(err)
	}
	dec.XORKeyStream(got, got)
	if !bytes.Equal(got, []byte("ping")) {
		t.Fatalf("payload=%q want ping", got)
	}
}
