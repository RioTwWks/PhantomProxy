package obfuscated2

import "crypto/cipher"

// ClientHeader создаёт 64-байтовый obfuscated2 заголовок клиента.
func ClientHeader(dcID int) ([]byte, error) {
	header, _, _, err := OutgoingHeader(dcID)
	return header, err
}

// ClientStreams возвращает заголовок и потоки шифрования клиента (Fake TLS, без секрета).
func ClientStreams(dcID int) ([]byte, cipher.Stream, cipher.Stream, error) {
	return OutgoingHeader(dcID)
}
