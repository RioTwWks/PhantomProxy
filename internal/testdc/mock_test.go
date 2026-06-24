package testdc

import (
	"io"
	"net"
	"testing"

	"github.com/RioTwWks/PhantomProxy/internal/obfuscated2"
)

func TestMockDCEcho(t *testing.T) {
	s, err := Start()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	header, enc, dec, err := obfuscated2.OutgoingHeader(2)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := conn.Write(header); err != nil {
		t.Fatal(err)
	}

	payload := []byte("hello-mtproto")
	cipher := make([]byte, len(payload))
	enc.XORKeyStream(cipher, payload)
	if _, err := conn.Write(cipher); err != nil {
		t.Fatal(err)
	}

	respCipher := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, respCipher); err != nil {
		t.Fatal(err)
	}
	dec.XORKeyStream(respCipher, respCipher)

	if string(respCipher) != string(payload) {
		t.Fatalf("echo = %q, want %q", respCipher, payload)
	}
}

func TestMockDCEchoViaPipe(t *testing.T) {
	payloads := make(chan []byte, 1)
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		_ = handleConn(server, payloads)
	}()

	header, enc, dec, err := obfuscated2.OutgoingHeader(2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(header); err != nil {
		t.Fatal(err)
	}
	cipher := make([]byte, len([]byte("ping")))
	enc.XORKeyStream(cipher, []byte("ping"))
	if _, err := client.Write(cipher); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 4)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatal(err)
	}
	dec.XORKeyStream(resp, resp)
	if string(resp) != "ping" {
		t.Fatalf("got %q", resp)
	}
}
