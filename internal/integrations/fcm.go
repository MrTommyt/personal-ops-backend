package integrations

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type FCMClient struct {
	Enabled     bool
	ProjectID   string
	ClientEmail string
	PrivateKey  string
	HTTP        *http.Client

	mu        sync.Mutex
	accessTok string
	expiresAt time.Time
}

func NewFCMClient(enabled bool, projectID, email, privateKey string) *FCMClient {
	return &FCMClient{
		Enabled:     enabled,
		ProjectID:   projectID,
		ClientEmail: email,
		PrivateKey:  privateKey,
		HTTP:        &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *FCMClient) Send(ctx context.Context, token, title, body string, data map[string]string) error {
	if !c.Enabled || c.ProjectID == "" {
		return nil
	}
	acc, err := c.getAccessToken(ctx)
	if err != nil {
		return err
	}
	payload := map[string]any{
		"message": map[string]any{
			"token": token,
			"notification": map[string]string{"title": title, "body": body},
			"data":         data,
		},
	}
	b, _ := json.Marshal(payload)
	url := fmt.Sprintf("https://fcm.googleapis.com/v1/projects/%s/messages:send", c.ProjectID)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+acc)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		if resp.StatusCode == 404 || resp.StatusCode == 410 {
			return fmt.Errorf("invalid_token")
		}
		return fmt.Errorf("fcm status %d", resp.StatusCode)
	}
	return nil
}

func (c *FCMClient) getAccessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.accessTok != "" && time.Now().Before(c.expiresAt.Add(-time.Minute)) {
		tok := c.accessTok
		c.mu.Unlock()
		return tok, nil
	}
	c.mu.Unlock()

	jwtToken, err := c.buildJWT()
	if err != nil {
		return "", err
	}
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", jwtToken)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("oauth status %d", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	c.mu.Lock()
	c.accessTok = out.AccessToken
	c.expiresAt = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	c.mu.Unlock()
	return out.AccessToken, nil
}

func (c *FCMClient) buildJWT() (string, error) {
	block, _ := pem.Decode([]byte(c.PrivateKey))
	if block == nil {
		return "", fmt.Errorf("invalid private key pem")
	}
	pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	rsaPK, ok := pk.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("private key is not rsa")
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   c.ClientEmail,
		"scope": "https://www.googleapis.com/auth/firebase.messaging",
		"aud":   "https://oauth2.googleapis.com/token",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return t.SignedString(rsaPK)
}
