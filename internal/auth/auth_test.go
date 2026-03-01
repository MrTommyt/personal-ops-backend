package auth

import (
	"testing"
	"time"
)

func TestPasswordHashAndVerify(t *testing.T) {
	h, err := HashPassword("super-secret", ArgonParams{MemoryKB: 64 * 1024, Iter: 1, Parallel: 1, KeyLen: 32})
	if err != nil {
		t.Fatalf("hash error: %v", err)
	}
	if !VerifyPassword(h, "super-secret") {
		t.Fatal("expected password to verify")
	}
	if VerifyPassword(h, "wrong") {
		t.Fatal("expected wrong password not to verify")
	}
}

func TestJWTIssueAndParse(t *testing.T) {
	tm := TokenManager{AccessSecret: []byte("a"), RefreshSecret: []byte("b"), AccessTTL: time.Minute, RefreshTTL: time.Hour}
	tok, err := tm.NewAccessToken("u1")
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	claims, err := tm.ParseAccess(tok)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if claims.UserID != "u1" {
		t.Fatalf("unexpected uid: %s", claims.UserID)
	}
}
