package telegram

import "fmt"

// dcAddresses — IP-адреса дата-центров Telegram.
// Положительные ключи — main DC, отрицательные — MEDIA DC (|id|).
// Адреса совместимы с встроенными defaults tdesktop / mtprotoproxy;
// media-only IP из help.getConfig клиент получает сам, здесь — стабильный fallback.
var dcAddresses = map[int][]string{
	1:  {"149.154.175.50:443"},
	-1: {"149.154.175.50:443"},
	2:  {"149.154.167.51:443", "95.161.76.100:443"},
	-2: {"149.154.167.51:443", "95.161.76.100:443"},
	3:  {"149.154.175.100:443"},
	-3: {"149.154.175.100:443"},
	4:  {"149.154.167.91:443"},
	-4: {"149.154.167.91:443"},
	5:  {"149.154.171.5:443"},
	-5: {"149.154.171.5:443"},
}

// ResolveAddr возвращает адрес DC или явно заданный backend.
// dc > 0 — main DC N; dc < 0 — MEDIA DC |dc|; dc == 0 — DC2.
func ResolveAddr(dcID int, backend string) (string, error) {
	if backend != "" {
		return backend, nil
	}

	id := dcID
	if id == 0 {
		id = 2
	}

	if addrs, ok := dcAddresses[id]; ok && len(addrs) > 0 {
		return addrs[0], nil
	}

	// Fallback: если есть только «парный» ключ (main↔media).
	alt := -id
	if addrs, ok := dcAddresses[alt]; ok && len(addrs) > 0 {
		return addrs[0], nil
	}

	return "", fmt.Errorf("неизвестный DC %d", dcID)
}
