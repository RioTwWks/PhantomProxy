package obfuscated2

import "crypto/cipher"

// ClientHeader создаёт 64-байтовый obfuscated2 заголовок клиента.
func ClientHeader(dcID int) ([]byte, error) {
	header, _, _, err := OutgoingHeader(dcID)
	return header, err
}

// ClientStreams возвращает заголовок для прямого соединения к DC (без секрета прокси).
func ClientStreams(dcID int) ([]byte, cipher.Stream, cipher.Stream, error) {
	return OutgoingHeader(dcID)
}

// ClientStreamsForFakeTLS — obfuscated2 после Fake TLS handshake (ee-секрет с deriveKey).
func ClientStreamsForFakeTLS(dcID int, secret []byte) ([]byte, cipher.Stream, cipher.Stream, error) {
	return OutgoingHeaderWithSecret(dcID, secret)
}
