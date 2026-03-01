package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenManager struct {
	AccessSecret  []byte
	RefreshSecret []byte
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
}

type Claims struct {
	UserID string `json:"uid"`
	jwt.RegisteredClaims
}

func (tm TokenManager) NewAccessToken(userID string) (string, error) {
	return tm.newToken(userID, tm.AccessSecret, tm.AccessTTL)
}

func (tm TokenManager) NewRefreshToken(userID string) (string, error) {
	return tm.newToken(userID, tm.RefreshSecret, tm.RefreshTTL)
}

func (tm TokenManager) newToken(userID string, secret []byte, ttl time.Duration) (string, error) {
	now := time.Now().UTC()
	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(secret)
}

func (tm TokenManager) ParseAccess(token string) (*Claims, error) {
	return parse(token, tm.AccessSecret)
}

func (tm TokenManager) ParseRefresh(token string) (*Claims, error) {
	return parse(token, tm.RefreshSecret)
}

func parse(token string, secret []byte) (*Claims, error) {
	c := &Claims{}
	_, err := jwt.ParseWithClaims(token, c, func(t *jwt.Token) (any, error) {
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

func HashOpaque(value string) string {
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:])
}
