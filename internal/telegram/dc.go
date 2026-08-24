package telegram

import "fmt"

// dcAddresses — IP-адреса дата-центров Telegram.
// Положительные ключи — main DC; отрицательные — MEDIA (media_only из getConfig / публичные карты).
// Источники: tdesktop BuiltInDc + известные media_only IPv4 (не тот же IP «автоматом»).
var dcAddresses = map[int][]string{
	1: {"149.154.175.50:443", "149.154.175.53:443"},
	2: {"149.154.167.51:443", "95.161.76.100:443"},
	3: {"149.154.175.100:443"},
	4: {"149.154.167.91:443"},
	5: {"149.154.171.5:443", "91.108.56.100:443"},

	// MEDIA DC (|id|): отдельные media_only хосты, не дубли main.
	-1: {"149.154.175.52:443"},
	-2: {"149.154.167.151:443", "149.154.167.222:443", "149.154.167.223:443"},
	-3: {"149.154.175.102:443"},
	-4: {"149.154.164.250:443", "149.154.166.120:443", "149.154.167.118:443"},
	-5: {"91.108.56.102:443", "91.108.56.128:443", "91.108.56.151:443"},
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

	return "", fmt.Errorf("неизвестный DC %d", dcID)
}
