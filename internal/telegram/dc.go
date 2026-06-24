package telegram

import "fmt"

// dcAddresses — IP-адреса дата-центров Telegram.
var dcAddresses = map[int][]string{
	1: {"149.154.175.50:443"},
	2: {"149.154.167.51:443", "95.161.76.100:443"},
	3: {"149.154.175.100:443"},
	4: {"149.154.167.91:443"},
	5: {"149.154.171.5:443"},
}

// ResolveAddr возвращает адрес DC или явно заданный backend.
func ResolveAddr(dcID int, backend string) (string, error) {
	if backend != "" {
		return backend, nil
	}

	id := dcID
	if id < 0 {
		id = -id
	}
	if id == 0 {
		id = 2
	}

	addrs, ok := dcAddresses[id]
	if !ok || len(addrs) == 0 {
		return "", fmt.Errorf("неизвестный DC %d", dcID)
	}
	return addrs[0], nil
}
