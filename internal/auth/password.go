package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

type ArgonParams struct {
	MemoryKB uint32
	Iter     uint32
	Parallel uint8
	KeyLen   uint32
}

func HashPassword(password string, p ArgonParams) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, p.Iter, p.MemoryKB, p.Parallel, p.KeyLen)
	return fmt.Sprintf("%d$%d$%d$%s$%s", p.MemoryKB, p.Iter, p.Parallel, b64(salt), b64(key)), nil
}

func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 {
		return false
	}
	memory, iter, parallel, err := parseParams(parts[0], parts[1], parts[2])
	if err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, iter, memory, parallel, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func b64(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }

func parseParams(memoryS, iterS, parallelS string) (uint32, uint32, uint8, error) {
	var memory, iter uint32
	var parallel uint8
	_, err := fmt.Sscanf(memoryS+" "+iterS+" "+parallelS, "%d %d %d", &memory, &iter, &parallel)
	if err != nil {
		return 0, 0, 0, err
	}
	return memory, iter, parallel, nil
}
