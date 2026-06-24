package obfuscated2

import (
	"encoding/binary"
	"fmt"
	"net"
)

// TryParseHeader проверяет 64-байтовый obfuscated2 заголовок с заданным секретом.
func TryParseHeader(header []byte, secret []byte) (dcID int, ok bool) {
	if len(header) != 64 || len(secret) == 0 {
		return 0, false
	}

	reversed := make([]byte, 64)
	for i := 0; i < 64; i++ {
		reversed[i] = header[63-i]
	}

	decKey := deriveKey(header[8:40], secret)
	decIV := make([]byte, 16)
	copy(decIV, header[40:56])
	dec := newCTR(decKey[:], decIV)

	decrypted := make([]byte, 64)
	dec.XORKeyStream(decrypted, header)

	connType := binary.LittleEndian.Uint32(decrypted[56:60])
	if connType != connTypePaddedIntermediate {
		return 0, false
	}

	dcID = int(int16(binary.LittleEndian.Uint16(decrypted[60:62])))
	return dcID, true
}

// ConnFromHeader создаёт Conn из уже прочитанного заголовка (dd-режим).
func ConnFromHeader(conn net.Conn, header []byte, secret []byte) (*Conn, int, error) {
	dcID, ok := TryParseHeader(header, secret)
	if !ok {
		return nil, 0, fmt.Errorf("неверный obfuscated2 заголовок")
	}

	reversed := make([]byte, 64)
	for i := 0; i < 64; i++ {
		reversed[i] = header[63-i]
	}

	encKey := deriveKey(reversed[8:40], secret)
	encIV := make([]byte, 16)
	copy(encIV, reversed[40:56])

	decKey := deriveKey(header[8:40], secret)
	decIV := make([]byte, 16)
	copy(decIV, header[40:56])

	return &Conn{
		Conn:      conn,
		EncStream: newCTR(encKey[:], encIV),
		DecStream: newCTR(decKey[:], decIV),
	}, dcID, nil
}
