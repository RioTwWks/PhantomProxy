package testclient

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

const (
	// reqPQMulti — TL constructor req_pq_multi (#be7e8ef1).
	reqPQMulti = 0xbe7e8ef1
	// resPQ — TL constructor resPQ.
	resPQ = 0x05162463
)

// BuildReqPQMulti формирует незашифрованный MTProto req_pq_multi.
func BuildReqPQMulti() ([]byte, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	const msgDataLen = 20
	pkt := make([]byte, 8+8+4+msgDataLen)
	now := time.Now()
	// msg_id ≈ unixtime*2^32, клиентские id кратны 4, нижние биты не нулевые.
	msgID := (uint64(now.Unix()) << 32) | (uint64(now.Nanosecond()) & 0xfffffffc)
	binary.LittleEndian.PutUint64(pkt[8:16], msgID)
	binary.LittleEndian.PutUint32(pkt[16:20], msgDataLen)
	binary.LittleEndian.PutUint32(pkt[20:24], reqPQMulti)
	copy(pkt[24:40], nonce)
	return pkt, nil
}

// WritePaddedIntermediate отправляет сообщение в формате padded intermediate.
func WritePaddedIntermediate(w io.Writer, payload []byte) error {
	pad := (4 - len(payload)%4) % 4
	if pad > 0 {
		payload = append(append([]byte{}, payload...), make([]byte, pad)...)
	}
	hdr := make([]byte, 4)
	binary.LittleEndian.PutUint32(hdr, uint32(len(payload)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadPaddedIntermediate читает ответ в формате padded intermediate.
func ReadPaddedIntermediate(r io.Reader) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(lenBuf) & 0x7fffffff
	if n == 0 || n > 1<<20 {
		return nil, fmt.Errorf("некорректная длина кадра: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// IsResPQ проверяет, что ответ — resPQ (незашифрованный MTProto).
func IsResPQ(frame []byte) bool {
	if len(frame) < 24 {
		return false
	}
	// auth_key_id (8) + message_id (8) + msg_len (4) + constructor (4)
	return binary.LittleEndian.Uint32(frame[20:24]) == resPQ
}
