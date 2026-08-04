package fallback_test

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/RioTwWks/PhantomProxy/internal/fallback"
)

func TestHoneypotGET(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_ = fallback.Serve(server, fallback.Options{Honeypot: true})
	}()

	_, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp, "200") {
		t.Fatalf("ответ = %q", resp)
	}
}

func TestHoneypotHEAD(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_ = fallback.Serve(server, fallback.Options{Honeypot: true})
	}()

	_, err := client.Write([]byte("HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp, "200") {
		t.Fatalf("ответ = %q", resp)
	}
}
