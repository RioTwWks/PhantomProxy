package faketls

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/RioTwWks/PhantomProxy/internal/mtproto"
	utls "github.com/refraction-networking/utls"
)

// RecordPolicy задаёт динамический размер TLS Application Data записей.
type RecordPolicy struct {
	MinChunk       int
	MaxChunk       int
	EnableDRS      bool
	EnableSplitTLS bool
}

// DefaultRecordPolicy возвращает политику по умолчанию с рандомизацией размера.
func DefaultRecordPolicy() RecordPolicy {
	return RecordPolicy{MinChunk: 512, MaxChunk: 4096}
}

// Normalize приводит политику к допустимым значениям.
func (p RecordPolicy) Normalize() RecordPolicy {
	if p.MinChunk <= 0 {
		p.MinChunk = 512
	}
	if p.MaxChunk <= 0 {
		p.MaxChunk = 4096
	}
	if p.MaxChunk > maxRecordPayload {
		p.MaxChunk = maxRecordPayload
	}
	if p.MinChunk > p.MaxChunk {
		p.MinChunk = p.MaxChunk
	}
	return p
}

func (p RecordPolicy) chunkSize(remaining int) int {
	p = p.Normalize()
	if remaining <= p.MinChunk {
		return remaining
	}
	span := p.MaxChunk - p.MinChunk + 1
	size := p.MinChunk + randInt(span)
	if size > remaining {
		size = remaining
	}
	if size > maxRecordPayload {
		size = maxRecordPayload
	}
	return size
}

// BuildClientHello создаёт валидный Fake TLS ClientHello для тестов и клиентов.
func BuildClientHello(secret mtproto.Secret) (*ClientHello, error) {
	record, err := generateClientHelloRecord(secret.Host, secret.Key[:])
	if err != nil {
		return nil, err
	}

	ch := &ClientHello{Raw: record}
	copy(ch.Random[:], record[randomOffset:randomOffset+randomLength])

	payload := record[5:]
	helloLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	hello := payload[4 : 4+helloLen]
	pos := 34
	sidLen := int(hello[pos])
	pos++
	ch.SessionID = make([]byte, sidLen)
	copy(ch.SessionID, hello[pos:pos+sidLen])
	pos += sidLen
	if pos+2 <= len(hello) {
		csLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
		pos += 2
		if csLen >= 2 {
			ch.CipherSuite = binary.BigEndian.Uint16(hello[pos : pos+2])
		}
	}

	return ch, nil
}

// ValidateClientHello проверяет HMAC и SNI ClientHello.
func ValidateClientHello(ch *ClientHello, secret []byte, hostname string) error {
	if ch.SNI() != "" && hostname != "" && ch.SNI() != hostname {
		return fmt.Errorf("SNI %q не совпадает с %q", ch.SNI(), hostname)
	}
	return validateClientHello(ch, secret)
}

// WriteClientHello отправляет Fake TLS ClientHello в соединение.
func WriteClientHello(conn io.Writer, secret mtproto.Secret) (*ClientHello, error) {
	ch, err := BuildClientHello(secret)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(ch.Raw); err != nil {
		return nil, err
	}
	return ch, nil
}

// ReadServerHandshake читает ответ Fake TLS сервера (ServerHello + CCS + AppData).
func ReadServerHandshake(conn io.Reader) error {
	readRecord := func() error {
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			return err
		}
		payloadLen := int(binary.BigEndian.Uint16(header[3:5]))
		payload := make([]byte, payloadLen)
		_, err := io.ReadFull(conn, payload)
		return err
	}

	if err := readRecord(); err != nil {
		return fmt.Errorf("server hello: %w", err)
	}
	if err := readRecord(); err != nil {
		return fmt.Errorf("change cipher: %w", err)
	}
	if err := readRecord(); err != nil {
		return fmt.Errorf("application data: %w", err)
	}
	return nil
}

func generateClientHelloRecord(domain string, secret []byte) ([]byte, error) {
	cfg := &utls.Config{
		ServerName: domain,
		Rand:       rand.Reader,
	}
	uconn := utls.UClient(nil, cfg, utls.HelloChrome_Auto)
	if err := uconn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("сборка ClientHello: %w", err)
	}

	hello := uconn.HandshakeState.Hello.Raw
	record := make([]byte, 0, 5+len(hello))
	record = append(record, recordHandshake, 0x03, 0x01)
	record = append(record, byte(len(hello)>>8), byte(len(hello)))
	record = append(record, hello...)

	if len(record) < randomOffset+randomLength {
		return nil, fmt.Errorf("ClientHello слишком короткий: %d", len(record))
	}

	random := record[randomOffset : randomOffset+randomLength]
	for i := range random {
		random[i] = 0
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(record)
	copy(random, mac.Sum(nil))

	ts := uint32(time.Now().Unix())
	old := binary.LittleEndian.Uint32(random[randomLength-4:])
	binary.LittleEndian.PutUint32(random[randomLength-4:], old^ts)

	return record, nil
}

// DialFakeTLS подключается к прокси и завершает Fake TLS handshake.
func DialFakeTLS(addr string, secret mtproto.Secret) (net.Conn, *ClientHello, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, nil, err
	}

	ch, err := WriteClientHello(conn, secret)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	if err := ReadServerHandshake(conn); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return conn, ch, nil
}

// NoiseParams управляет размером padding в ServerHello.
type NoiseParams struct {
	Mean   int
	Jitter int
}

// WriteServerHelloWithNoise отправляет ServerHello с настраиваемым padding.
func WriteServerHelloWithNoise(conn net.Conn, ch *ClientHello, secret []byte, noise NoiseParams) error {
	var buf bytes.Buffer

	writeRecord(&buf, recordHandshake, buildServerHello(ch))
	writeRecord(&buf, recordChangeCipher, []byte{0x01})

	padLen := noise.paddingLen()
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

func (n NoiseParams) paddingLen() int {
	if n.Mean <= 0 {
		return 1024 + randInt(3072)
	}
	jitter := n.Jitter
	if jitter <= 0 {
		jitter = 512
	}
	size := n.Mean - jitter + randInt(2*jitter)
	if size < 1000 {
		size = 1000
	}
	return size
}
