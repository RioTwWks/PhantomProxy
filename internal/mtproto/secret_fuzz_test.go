package mtproto

import "testing"

func FuzzParseSecret(f *testing.F) {
	f.Add("ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d")
	f.Add("dd0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f.Add("bad")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseSecret(s)
	})
}
