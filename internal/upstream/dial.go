package upstream

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// Dialer создаёт TCP-соединения к DC с учётом SOCKS5 и prefer IP.
type Dialer struct {
	SOCKS5    string
	PreferIP  string
	Timeout   time.Duration
}

// DialContext подключается к addr.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d == nil {
		d = &Dialer{}
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	network = resolveNetwork(network, d.PreferIP)

	var dialer proxy.Dialer = &net.Dialer{Timeout: timeout}
	if d.SOCKS5 != "" {
		socks, err := proxy.SOCKS5("tcp", d.SOCKS5, nil, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("SOCKS5 %s: %w", d.SOCKS5, err)
		}
		dialer = socks
	}

	if cd, ok := dialer.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, network, addr)
	}
	return dialer.Dial(network, addr)
}

func resolveNetwork(network, prefer string) string {
	prefer = strings.ToLower(strings.TrimSpace(prefer))
	switch prefer {
	case "only-ipv4", "ipv4":
		if network == "tcp" {
			return "tcp4"
		}
	case "only-ipv6", "ipv6":
		if network == "tcp" {
			return "tcp6"
		}
	case "prefer-ipv6":
		if network == "tcp" {
			return "tcp"
		}
	}
	return network
}
