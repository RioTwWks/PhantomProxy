package testclient

import (
	"bytes"
	"testing"
)

func TestBuildReqPQMultiAndResPQ(t *testing.T) {
	pkt, err := BuildReqPQMulti()
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt) != 40 {
		t.Fatalf("len=%d", len(pkt))
	}

	var buf bytes.Buffer
	if err := WritePaddedIntermediate(&buf, pkt); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 44 {
		t.Fatalf("framed len=%d", buf.Len())
	}

	got, err := ReadPaddedIntermediate(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pkt) {
		t.Fatal("roundtrip mismatch")
	}

	// симуляция resPQ
	res := make([]byte, 40)
	res[20] = 0x63
	res[21] = 0x24
	res[22] = 0x16
	res[23] = 0x05
	if !IsResPQ(res) {
		t.Fatal("IsResPQ failed")
	}
}
