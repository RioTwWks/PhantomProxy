package user

import (
	"testing"

	"github.com/RioTwWks/PhantomProxy/internal/faketls"
	"github.com/RioTwWks/PhantomProxy/internal/mtproto"
)

func TestMatchClientHelloMultiUser(t *testing.T) {
	t.Parallel()

	const secret1 = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
	const secret2 = "ee0123456789abcdef0123456789abcdef6578616d706c652e636f6d"

	s1, err := mtproto.ParseSecret(secret1)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := mtproto.ParseSecret(secret2)
	if err != nil {
		t.Fatal(err)
	}

	mgr, err := NewManager([]User{
		{Name: "alice", Secret: s1, Enabled: true},
		{Name: "bob", Secret: s2, Enabled: true},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	ch1, err := faketls.BuildClientHello(s1)
	if err != nil {
		t.Fatal(err)
	}
	u, err := mgr.MatchClientHello(ch1)
	if err != nil {
		t.Fatalf("match alice: %v", err)
	}
	if u.Name != "alice" {
		t.Fatalf("user = %q", u.Name)
	}

	ch2, err := faketls.BuildClientHello(s2)
	if err != nil {
		t.Fatal(err)
	}
	u, err = mgr.MatchClientHello(ch2)
	if err != nil {
		t.Fatalf("match bob: %v", err)
	}
	if u.Name != "bob" {
		t.Fatalf("user = %q", u.Name)
	}
}

func TestUserCRUD(t *testing.T) {
	t.Parallel()

	s1, _ := mtproto.ParseSecret("ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d")
	s2, _ := mtproto.ParseSecret("ee0123456789abcdef0123456789abcdef6578616d706c652e636f6d")

	mgr, err := NewManager([]User{{Name: "alice", Secret: s1, Enabled: true}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := mgr.AddUser(User{Name: "bob", Secret: s2, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if len(mgr.Users()) != 2 {
		t.Fatalf("users = %d", len(mgr.Users()))
	}

	disabled := false
	if _, err := mgr.UpdateUser("bob", nil, &disabled); err != nil {
		t.Fatal(err)
	}

	if err := mgr.RemoveUser("bob"); err != nil {
		t.Fatal(err)
	}
	if len(mgr.Users()) != 1 {
		t.Fatalf("users after remove = %d", len(mgr.Users()))
	}
}

func TestMatchClientHelloJA3Whitelist(t *testing.T) {
	t.Parallel()

	secret, err := mtproto.ParseSecret("ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d")
	if err != nil {
		t.Fatal(err)
	}

	ch, err := faketls.BuildClientHello(secret)
	if err != nil {
		t.Fatal(err)
	}
	ja3 := faketls.JA3(ch.Raw)

	mgrBlocked, err := NewManager([]User{{Name: "alice", Secret: secret, Enabled: true}}, []string{"deadbeef"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgrBlocked.MatchClientHello(ch); err == nil {
		t.Fatal("ожидался отказ по JA3 whitelist")
	}

	mgr, err := NewManager([]User{{Name: "alice", Secret: secret, Enabled: true}}, []string{ja3}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := mgr.MatchClientHello(ch); err != nil {
		t.Fatalf("whitelist match: %v", err)
	}
}
