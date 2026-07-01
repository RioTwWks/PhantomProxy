package proxy

import "net"

func splitHostPort(remote string) (host string, port int) {
	if remote == "" {
		return "127.0.0.1", 0
	}
	host, portStr, err := net.SplitHostPort(remote)
	if err != nil {
		return remote, 0
	}
	host = stripBrackets(host)
	var p int
	for _, c := range portStr {
		if c < '0' || c > '9' {
			break
		}
		p = p*10 + int(c-'0')
	}
	return host, p
}

func stripBrackets(host string) string {
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		return host[1 : len(host)-1]
	}
	return host
}
