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

// Serve проксирует HTTP-запрос на upstream-заглушку.
func Serve(client net.Conn, upstream string) error {
	reader := bufio.NewReader(client)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return serveStatic(client)
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
		return serveStatic(client)
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	if err := resp.Write(&buf); err != nil {
		return err
	}
	_, err = client.Write(buf.Bytes())
	return err
}

func serveStatic(client net.Conn) error {
	body := `<!DOCTYPE html>
<html lang="ru">
<head><meta charset="utf-8"><title>Welcome</title></head>
<body><h1>Welcome</h1><p>Service is running.</p></body>
</html>`
	response := "HTTP/1.1 200 OK\r\n" +
		"Connection: close\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)) +
		body
	_, err := io.Copy(client, strings.NewReader(response))
	return err
}
