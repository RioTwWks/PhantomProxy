package faketls

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"
)

const (
	recordHandshake       byte = 0x16
	recordChangeCipher    byte = 0x14
	recordApplicationData byte = 0x17
	maxRecordPayload           = 16384
	randomOffset               = 11
	randomLength               = 32
	timestampSkewSeconds       = 120
)

var (
	errNotHandshake   = errors.New("не TLS handshake")
	errNotClientHello = errors.New("не ClientHello")
	errBadDigest      = errors.New("неверный HMAC в ClientRandom")
	errTimestamp      = errors.New("метка времени вне допустимого окна")
)

// ClientHello — распарсенный TLS ClientHello клиента MTProto.
type ClientHello struct {
	Raw         []byte
	Random      [randomLength]byte
	SessionID   []byte
	CipherSuite uint16
}

// ReadClientHello читает и проверяет Fake TLS ClientHello.
func ReadClientHello(conn net.Conn, secret []byte, hostname string) (*ClientHello, error) {
	ch, err := parseClientHello(conn)
	if err != nil {
		return nil, err
	}

	if ch.SNI() != "" && ch.SNI() != hostname {
		return nil, fmt.Errorf("SNI %q не совпадает с %q", ch.SNI(), hostname)
	}

	if err := validateClientHello(ch, secret); err != nil {
		return nil, err
	}

	return ch, nil
}

// SNI извлекает hostname из ClientHello.
func (ch *ClientHello) SNI() string {
	if len(ch.Raw) < 5 {
		return ""
	}
	payload := ch.Raw[5:]
	if len(payload) < 4 || payload[0] != 0x01 {
		return ""
	}

	helloLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	hello := payload[4:]
	if len(hello) < helloLen {
		return ""
	}
	hello = hello[:helloLen]

	pos := 2 + 32 // version + random
	if pos >= len(hello) {
		return ""
	}

	sidLen := int(hello[pos])
	pos++
	pos += sidLen

	if pos+2 > len(hello) {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2 + csLen

	if pos >= len(hello) {
		return ""
	}
	compLen := int(hello[pos])
	pos++
	pos += compLen

	if pos+2 > len(hello) {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2
	return parseSNI(hello[pos : pos+extLen])
}

func parseClientHello(conn io.Reader) (*ClientHello, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("чтение заголовка TLS-записи: %w", err)
	}
	if header[0] != recordHandshake {
		return nil, errNotHandshake
	}

	payloadLen := int(binary.BigEndian.Uint16(header[3:5]))
	if payloadLen > maxRecordPayload+2048 {
		return nil, errors.New("TLS-запись слишком большая")
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, fmt.Errorf("чтение ClientHello: %w", err)
	}

	fullRecord := append(header, payload...)
	if len(payload) < 4 || payload[0] != 0x01 {
		return nil, errNotClientHello
	}

	helloLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	hello := payload[4:]
	if len(hello) < helloLen {
		return nil, errors.New("ClientHello обрезан")
	}
	hello = hello[:helloLen]

	if len(hello) < 34 {
		return nil, errors.New("ClientHello слишком короткий")
	}

	ch := &ClientHello{Raw: fullRecord}
	copy(ch.Random[:], hello[2:34])
	pos := 34

	sidLen := int(hello[pos])
	pos++
	ch.SessionID = make([]byte, sidLen)
	copy(ch.SessionID, hello[pos:pos+sidLen])
	pos += sidLen

	csLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2
	if csLen >= 2 {
		ch.CipherSuite = binary.BigEndian.Uint16(hello[pos : pos+2])
	}

	return ch, nil
}

func parseSNI(extensions []byte) string {
	pos := 0
	for pos+4 <= len(extensions) {
		extType := binary.BigEndian.Uint16(extensions[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(extensions[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > len(extensions) {
			break
		}
		if extType == 0x0000 {
			data := extensions[pos : pos+extLen]
			if len(data) < 2 {
				break
			}
			data = data[2:]
			for len(data) >= 3 {
				nameType := data[0]
				nameLen := int(binary.BigEndian.Uint16(data[1:3]))
				data = data[3:]
				if nameLen > len(data) {
					break
				}
				if nameType == 0 {
					return string(data[:nameLen])
				}
				data = data[nameLen:]
			}
		}
		pos += extLen
	}
	return ""
}

func validateClientHello(ch *ClientHello, secret []byte) error {
	if len(ch.Raw) < randomOffset+randomLength {
		return errors.New("сырая запись слишком короткая")
	}

	modified := make([]byte, len(ch.Raw))
	copy(modified, ch.Raw)
	for i := 0; i < randomLength; i++ {
		modified[randomOffset+i] = 0
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(modified)
	computed := mac.Sum(nil)

	for i := 0; i < randomLength; i++ {
		computed[i] ^= ch.Random[i]
	}

	var zeros [randomLength]byte
	if subtle.ConstantTimeCompare(zeros[:randomLength-4], computed[:randomLength-4]) != 1 {
		return errBadDigest
	}

	ts := int64(binary.LittleEndian.Uint32(computed[randomLength-4:]))
	diff := time.Now().Unix() - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > timestampSkewSeconds {
		return errTimestamp
	}

	return nil
}

// WriteServerHello отправляет синтетический TLS ServerHello + CCS + ApplicationData.
func WriteServerHello(conn net.Conn, ch *ClientHello, secret []byte) error {
	var buf bytes.Buffer

	writeRecord(&buf, recordHandshake, buildServerHello(ch))
	writeRecord(&buf, recordChangeCipher, []byte{0x01})

	padLen := 1024 + randInt(3072)
	pad := make([]byte, padLen)
	if _, err := rand.Read(pad); err != nil {
		return fmt.Errorf("генерация padding: %w", err)
	}
	writeRecord(&buf, recordApplicationData, pad)

	packet := buf.Bytes()
	for i := 0; i < randomLength; i++ {
		packet[randomOffset+i] = 0
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(ch.Random[:])
	mac.Write(packet)
	copy(packet[randomOffset:randomOffset+randomLength], mac.Sum(nil))

	_, err := conn.Write(packet)
	return err
}

func buildServerHello(ch *ClientHello) []byte {
	var hello bytes.Buffer

	hello.WriteByte(0x02)
	hello.Write([]byte{0, 0, 0})
	hello.Write([]byte{0x03, 0x03})

	serverRandom := make([]byte, 32)
	_, _ = rand.Read(serverRandom)
	hello.Write(serverRandom)

	hello.WriteByte(byte(len(ch.SessionID)))
	hello.Write(ch.SessionID)
	binary.Write(&hello, binary.BigEndian, ch.CipherSuite) //nolint:errcheck
	hello.WriteByte(0x00)

	var ext bytes.Buffer
	ext.Write([]byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04})

	pubKey := make([]byte, 32)
	_, _ = rand.Read(pubKey)
	keyShare := append([]byte{0x00, 0x1d, 0x00, 0x20}, pubKey...)
	ext.Write([]byte{0x00, 0x33})
	binary.Write(&ext, binary.BigEndian, uint16(len(keyShare))) //nolint:errcheck
	ext.Write(keyShare)

	binary.Write(&hello, binary.BigEndian, uint16(ext.Len())) //nolint:errcheck
	hello.Write(ext.Bytes())

	result := hello.Bytes()
	bodyLen := len(result) - 4
	result[1] = byte(bodyLen >> 16)
	result[2] = byte(bodyLen >> 8)
	result[3] = byte(bodyLen)
	return result
}

func writeRecord(buf *bytes.Buffer, recType byte, payload []byte) {
	buf.WriteByte(recType)
	buf.Write([]byte{0x03, 0x03})
	binary.Write(buf, binary.BigEndian, uint16(len(payload))) //nolint:errcheck
	buf.Write(payload)
}

func randInt(max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}
