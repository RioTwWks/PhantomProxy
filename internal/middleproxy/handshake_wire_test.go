package middleproxy

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
	"time"
)

func TestWriteFrameWireFormat(t *testing.T) {
	msg := make([]byte, 32)
	copy(msg, []byte{0xaa, 0x87, 0xcb, 0x7a})
	copy(msg[4:8], DefaultProxySecret[:4])
	binary.LittleEndian.PutUint32(msg[8:12], 1)
	binary.LittleEndian.PutUint32(msg[12:16], uint32(time.Now().Unix()))

	var buf bytes.Buffer
	if err := writeFrame(&buf, -2, msg); err != nil {
		t.Fatal(err)
	}
	got := buf.Bytes()
	t.Logf("go wire len %d hex %s", len(got), hex.EncodeToString(got[:min(20, len(got))]))
}

func TestNonceHandshakeLive(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}

	msg := make([]byte, 32)
	copy(msg, []byte{0xaa, 0x87, 0xcb, 0x7a})
	copy(msg[4:8], DefaultProxySecret[:4])
	binary.LittleEndian.PutUint32(msg[8:12], 1)
	binary.LittleEndian.PutUint32(msg[12:16], uint32(time.Now().Unix()))
	copy(msg[16:], []byte{0x63, 0x1b, 0xa9, 0x24, 0x67, 0x33, 0x6b, 0x8c, 0x7c, 0x08, 0xfe, 0xe6, 0x76, 0x19, 0xa3, 0x01})

	conn, err := net.DialTimeout("tcp", "149.154.161.144:8888", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := writeFrame(conn, -2, msg); err != nil {
		t.Fatal(err)
	}

	seq := int32(-2)
	ans, err := readFrame(conn, &seq)
	if err != nil {
		t.Fatal(err)
	}
	if len(ans) != 32 {
		t.Fatalf("ans len %d", len(ans))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
