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
	// SecurePrefix — префикс secure obfuscated2 (0xdd).
	SecurePrefix byte = 0xdd
	// KeyLength — длина ключа в секрете.
	KeyLength = 16
)

var (
	// ErrEmptySecret возвращается при пустом секрете.
	ErrEmptySecret = errors.New("секрет пуст")
)

// Secret — распарсенный MTProto-секрет.
type Secret struct {
	Key  [KeyLength]byte
	Host string
	Mode byte // FakeTLSPrefix или SecurePrefix
}

// IsFakeTLS возвращает true для ee-секрета.
func (s Secret) IsFakeTLS() bool { return s.Mode == FakeTLSPrefix }

// IsSecure возвращает true для dd-секрета.
func (s Secret) IsSecure() bool { return s.Mode == SecurePrefix }

// ParseSecret разбирает hex- или base64-секрет Telegram (ee или dd).
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

	mode := decoded[0]
	if mode != FakeTLSPrefix && mode != SecurePrefix {
		return Secret{}, fmt.Errorf("ожидался префикс ee/dd, получен %#x", mode)
	}

	payload := decoded[1:]
	if len(payload) < KeyLength {
		return Secret{}, fmt.Errorf("ключ секрета короче %d байт", KeyLength)
	}

	var s Secret
	s.Mode = mode
	copy(s.Key[:], payload[:KeyLength])

	if mode == FakeTLSPrefix {
		s.Host = string(payload[KeyLength:])
		if s.Host == "" {
			return Secret{}, errors.New("hostname в ee-секрете пуст")
		}
	}

	return s, nil
}

// EncodeHex кодирует секрет в hex-строку для Telegram.
func EncodeHex(s Secret) string {
	data := append([]byte{s.Mode}, s.Key[:]...)
	if s.Mode == FakeTLSPrefix {
		data = append(data, s.Host...)
	}
	return hex.EncodeToString(data)
}

// EncodeSecureHex создаёт dd-секрет только с ключом.
func EncodeSecureHex(key [KeyLength]byte) string {
	data := append([]byte{SecurePrefix}, key[:]...)
	return hex.EncodeToString(data)
}
