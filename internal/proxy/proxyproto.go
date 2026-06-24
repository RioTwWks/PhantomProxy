package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
)

type remoteAddrString string

func (r remoteAddrString) Network() string { return "tcp" }
func (r remoteAddrString) String() string  { return string(r) }

type proxyConn struct {
	net.Conn
	reader *bufio.Reader
	remote net.Addr
}

func (p *proxyConn) Read(b []byte) (int, error) {
	return p.reader.Read(b)
}

func (p *proxyConn) RemoteAddr() net.Addr {
	return p.remote
}

type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekedConn) Read(b []byte) (int, error) {
	return p.r.Read(b)
}

// acceptWithProxyProtocol обрабатывает PROXY v1 при accept.
func acceptWithProxyProtocol(conn net.Conn, enabled bool) (net.Conn, error) {
	if !enabled {
		return conn, nil
	}

	br := bufio.NewReader(conn)
	head, err := br.Peek(6)
	if err != nil {
		if err == io.EOF {
			return conn, nil
		}
		return nil, err
	}
	if !bytes.Equal(head, []byte("PROXY ")) {
		return &peekedConn{Conn: conn, r: br}, nil
	}

	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSpace(line)
	parts := strings.Split(line, " ")
	if len(parts) < 6 {
		return nil, fmt.Errorf("некорректный PROXY v1")
	}

	remote := conn.RemoteAddr().String()
	if parts[1] == "TCP4" || parts[1] == "TCP6" {
		remote = net.JoinHostPort(parts[2], parts[4])
	}

	return &proxyConn{
		Conn:   conn,
		reader: br,
		remote: remoteAddrString(remote),
	}, nil
}
