package telegram

import "testing"

func TestResolveAddrMainAndMedia(t *testing.T) {
	cases := []struct {
		dcID    int
		wantSub string
		wantErr bool
	}{
		{2, "149.154.167.51:443", false},
		{-2, "149.154.167.151:443", false}, // media ≠ main
		{-1, "149.154.175.52:443", false},
		{0, "149.154.167.51:443", false},
		{65534, "", true},
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

func TestResolveAddrMediaDistinctFromMain(t *testing.T) {
	for _, id := range []int{1, 2, 3, 4, 5} {
		main, err := ResolveAddr(id, "")
		if err != nil {
			t.Fatalf("main %d: %v", id, err)
		}
		media, err := ResolveAddr(-id, "")
		if err != nil {
			t.Fatalf("media %d: %v", id, err)
		}
		if main == media {
			t.Errorf("DC %d: media IP совпадает с main (%s) — нужна отдельная таблица", id, main)
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
