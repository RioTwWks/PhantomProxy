package limit

import (
	"net"
	"testing"
)

type fakeAddr struct{ s string }

func (f fakeAddr) Network() string { return "tcp" }
func (f fakeAddr) String() string  { return f.s }

type fakeConn struct {
	net.Conn
	addr fakeAddr
}

func (f *fakeConn) RemoteAddr() net.Addr { return f.addr }

func TestConnLimiter(t *testing.T) {
	lim := NewConnLimiter(1)
	c1 := &fakeConn{addr: fakeAddr{"1.2.3.4:1000"}}
	c2 := &fakeConn{addr: fakeAddr{"1.2.3.4:1001"}}

	if !lim.Acquire(c1) {
		t.Fatal("первое соединение должно пройти")
	}
	if lim.Acquire(c2) {
		t.Fatal("второе с того же IP должно быть отклонено")
	}
	lim.Release(c1)
	if !lim.Acquire(c2) {
		t.Fatal("после release слот должен освободиться")
	}
}
