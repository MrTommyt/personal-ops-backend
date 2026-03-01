package util

import "testing"

func TestVerifyHMACSHA256Hex(t *testing.T) {
	body := []byte("hello")
	secret := "secret"
	good := "sha256=88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b"
	if !VerifyHMACSHA256Hex(body, secret, good) {
		t.Fatal("expected valid signature")
	}
	if VerifyHMACSHA256Hex(body, secret, "sha256=deadbeef") {
		t.Fatal("expected invalid signature")
	}
}
