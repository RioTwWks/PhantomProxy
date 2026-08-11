package middleproxy

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/RioTwWks/PhantomProxy/internal/testclient"
)

func TestIntermediateConnStripWrite(t *testing.T) {
	reqPQ, err := testclient.BuildReqPQMulti()
	if err != nil {
		t.Fatal(err)
	}
	var framed bytes.Buffer
	if err := testclient.WritePaddedIntermediate(&framed, reqPQ); err != nil {
		t.Fatal(err)
	}

	inner := &captureConn{}
	wrapped := wrapIntermediate(inner)
	if _, err := wrapped.Write(framed.Bytes()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(inner.data, reqPQ) {
		t.Fatalf("inner len=%d want %d", len(inner.data), len(reqPQ))
	}
}

func TestIntermediateConnAddRead(t *testing.T) {
	reqPQ, err := testclient.BuildReqPQMulti()
	if err != nil {
		t.Fatal(err)
	}

	inner := &captureConn{readData: reqPQ}
	wrapped := wrapIntermediate(inner)

	resp, err := testclient.ReadPaddedIntermediate(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resp, reqPQ) {
		t.Fatal("framed response mismatch")
	}
}

type captureConn struct {
	data     []byte
	readData []byte
}

func (c *captureConn) Read(p []byte) (int, error) {
	if len(c.readData) == 0 {
		return 0, nil
	}
	n := copy(p, c.readData)
	c.readData = c.readData[n:]
	return n, nil
}

func (c *captureConn) Write(p []byte) (int, error) {
	c.data = append(c.data, p...)
	return len(p), nil
}

func (c *captureConn) readPayload() ([]byte, error) {
	if len(c.readData) == 0 {
		return nil, io.EOF
	}
	out := c.readData
	c.readData = nil
	return out, nil
}

func (c *captureConn) Close() error                       { return nil }
func (c *captureConn) LocalAddr() net.Addr                { return nil }
func (c *captureConn) RemoteAddr() net.Addr               { return nil }
func (c *captureConn) SetDeadline(t time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(t time.Time) error { return nil }
