// Package testclient эмулирует Telegram MTProto-клиент (Fake TLS + obfuscated2).
package testclient

import (
	"io"
	"net"
	"time"

	"github.com/RioTwWks/PhantomProxy/internal/faketls"
	"github.com/RioTwWks/PhantomProxy/internal/mtproto"
	"github.com/RioTwWks/PhantomProxy/internal/obfuscated2"
)

// Client подключается к PhantomProxy как Telegram-клиент.
type Client struct {
	Secret mtproto.Secret
	DCID   int
	Policy faketls.RecordPolicy
}

// Dial устанавливает соединение и завершает handshake с прокси.
func (c *Client) Dial(proxyAddr string) (net.Conn, error) {
	conn, _, err := faketls.DialFakeTLS(proxyAddr, c.Secret)
	if err != nil {
		return nil, err
	}

	policy := c.Policy.Normalize()
	tlsConn := &faketls.RecordConn{Conn: conn, Policy: policy}

	dcID := c.DCID
	if dcID == 0 {
		dcID = 2
	}

	header, enc, dec, err := obfuscated2.ClientStreams(dcID)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if _, err := tlsConn.Write(header); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return &obfuscated2.Conn{
		Conn:      tlsConn,
		EncStream: enc,
		DecStream: dec,
	}, nil
}

// RoundTrip отправляет payload через прокси и ждёт эхо от mock DC.
func RoundTrip(conn net.Conn, payload []byte, timeout time.Duration) ([]byte, error) {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
