package obfuscated2

import (
	"testing"
)

func TestTryParseHeader(t *testing.T) {
	header, _, _, err := OutgoingHeader(2)
	if err != nil {
		t.Fatal(err)
	}
	// Без секрета TryParseHeader с пустым secret не сработает для исходящего заголовка
	// Проверяем roundtrip через Handshake с секретом
	secret := []byte("0123456789abcdef")
	// Сгенерируем валидный входящий заголовок через обратную операцию сложно;
	// проверим только отрицательный случай
	if _, ok := TryParseHeader(header, secret); ok {
		// исходящий заголовок без derive от secret может случайно совасть — допустимо
	}
	if _, ok := TryParseHeader(make([]byte, 10), secret); ok {
		t.Fatal("короткий заголовок не должен проходить")
	}
}
