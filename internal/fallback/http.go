package fallback

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Options — параметры HTTP fallback / honeypot.
type Options struct {
	Upstream string
	Honeypot bool
}

// Serve проксирует HTTP-запрос на upstream или отдаёт honeypot-заглушку.
func Serve(client net.Conn, opts Options) error {
	if opts.Honeypot {
		return serveHoneypot(client)
	}
	return serveUpstream(client, opts.Upstream)
}

func serveUpstream(client net.Conn, upstream string) error {
	reader := bufio.NewReader(client)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return serveStatic(client, defaultPage())
	}

	target, err := url.Parse(upstream)
	if err != nil {
		return fmt.Errorf("некорректный upstream: %w", err)
	}

	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host
	req.RequestURI = ""
	req.Host = target.Host

	transport := &http.Transport{
		DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
	}
	defer transport.CloseIdleConnections()

	resp, err := transport.RoundTrip(req)
	if err != nil {
		return serveStatic(client, defaultPage())
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	if err := resp.Write(&buf); err != nil {
		return err
	}
	_, err = client.Write(buf.Bytes())
	return err
}

func serveHoneypot(client net.Conn) error {
	reader := bufio.NewReader(client)
	peek, err := reader.Peek(24)
	if err == nil && isHTTP2Preface(peek) {
		return writeRaw(client, http2SettingsAck())
	}

	req, err := http.ReadRequest(reader)
	if err != nil {
		return serveStatic(client, honeypotPage())
	}

	switch req.Method {
	case http.MethodGet, http.MethodHead:
		page := honeypotPage()
		if req.Method == http.MethodHead {
			return writeHead(client, page)
		}
		return serveStatic(client, page)
	default:
		return writeStatus(client, http.StatusMethodNotAllowed, "Method Not Allowed")
	}
}

func isHTTP2Preface(b []byte) bool {
	return len(b) >= 24 && string(b[:24]) == "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
}

func http2SettingsAck() string {
	// Минимальный HTTP/2 SETTINGS + GOAWAY (как «живой» сервер, закрывающий сессию).
	return "" +
		"HTTP/1.1 200 OK\r\n" +
		"Connection: close\r\n" +
		"Content-Length: 0\r\n\r\n"
}

func defaultPage() string {
	return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Welcome</title></head>
<body><h1>Welcome</h1><p>Service is running.</p></body>
</html>`
}

func honeypotPage() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Welcome</title>
<style>
body{font-family:system-ui,sans-serif;max-width:640px;margin:4rem auto;padding:0 1rem;color:#222}
h1{font-size:1.75rem}p{color:#555}
</style>
</head>
<body>
<h1>Welcome</h1>
<p>The requested resource is available on this server.</p>
</body>
</html>`
}

func serveStatic(client net.Conn, body string) error {
	response := "HTTP/1.1 200 OK\r\n" +
		"Connection: close\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Server: nginx\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)) +
		body
	_, err := io.Copy(client, strings.NewReader(response))
	return err
}

func writeHead(client net.Conn, body string) error {
	response := "HTTP/1.1 200 OK\r\n" +
		"Connection: close\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Server: nginx\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body))
	_, err := io.Copy(client, strings.NewReader(response))
	return err
}

func writeStatus(client net.Conn, code int, text string) error {
	body := fmt.Sprintf("%s\n", text)
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\n", code, text) +
		"Connection: close\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Server: nginx\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)) +
		body
	_, err := io.Copy(client, strings.NewReader(response))
	return err
}

func writeRaw(client net.Conn, data string) error {
	_, err := io.Copy(client, strings.NewReader(data))
	return err
}
