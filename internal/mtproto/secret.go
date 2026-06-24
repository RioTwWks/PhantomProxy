package mtproto

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	// FakeTLSPrefix — префикс секрета Fake TLS (0xee).
	FakeTLSPrefix byte = 0xee
	// KeyLength — длина ключа в секрете.
	KeyLength = 16
)

var (
	// ErrEmptySecret возвращается при пустом секрете.
	ErrEmptySecret = errors.New("секрет пуст")
)

// Secret — распарсенный MTProto-секрет Fake TLS.
type Secret struct {
	Key  [KeyLength]byte
	Host string
}

// ParseSecret разбирает hex- или base64-секрет Telegram.
func ParseSecret(text string) (Secret, error) {
	if text == "" {
		return Secret{}, ErrEmptySecret
	}

	decoded, err := hex.DecodeString(text)
	if err != nil {
		decoded, err = base64.RawURLEncoding.DecodeString(text)
	}
	if err != nil {
		return Secret{}, fmt.Errorf("некорректный формат секрета: %w", err)
	}

	if len(decoded) < 2 {
		return Secret{}, fmt.Errorf("секрет слишком короткий: %d байт", len(decoded))
	}
	if decoded[0] != FakeTLSPrefix {
		return Secret{}, fmt.Errorf("ожидался префикс ee, получен %#x", decoded[0])
	}

	payload := decoded[1:]
	if len(payload) < KeyLength {
		return Secret{}, fmt.Errorf("ключ секрета короче %d байт", KeyLength)
	}

	var s Secret
	copy(s.Key[:], payload[:KeyLength])
	s.Host = string(payload[KeyLength:])
	if s.Host == "" {
		return Secret{}, errors.New("hostname в секрете пуст")
	}

	return s, nil
}
