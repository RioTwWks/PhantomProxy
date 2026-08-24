package telegram

import "testing"

func TestResolveAddrMainAndMedia(t *testing.T) {
	cases := []struct {
		dcID    int
		wantSub string // подстрока ожидаемого адреса
		wantErr bool
	}{
		{2, "149.154.167.51:443", false},
		{-2, "149.154.167.51:443", false},
		{-1, "149.154.175.50:443", false},
		{0, "149.154.167.51:443", false}, // default DC2
		{65534, "", true},                // unsigned -2; не валидный id
		{999, "", true},
	}
	for _, tc := range cases {
		addr, err := ResolveAddr(tc.dcID, "")
		if tc.wantErr {
			if err == nil {
				t.Errorf("dcID=%d: ожидалась ошибка, got %q", tc.dcID, addr)
			}
			continue
		}
		if err != nil {
			t.Errorf("dcID=%d: %v", tc.dcID, err)
			continue
		}
		if addr != tc.wantSub {
			t.Errorf("dcID=%d: addr=%q want %q", tc.dcID, addr, tc.wantSub)
		}
	}
}

func TestResolveAddrBackendOverride(t *testing.T) {
	addr, err := ResolveAddr(-2, "10.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	if addr != "10.0.0.1:443" {
		t.Fatalf("got %q", addr)
	}
}

func TestResolveAddrSignedBoundary(t *testing.T) {
	// int16(-2) как uint16 == 65534 — не должен резолвиться.
	if _, err := ResolveAddr(65534, ""); err == nil {
		t.Fatal("65534 не должен быть валидным DC id")
	}
	addr, err := ResolveAddr(-2, "")
	if err != nil {
		t.Fatal(err)
	}
	if addr == "" {
		t.Fatal("пустой адрес для media DC2")
	}
}
