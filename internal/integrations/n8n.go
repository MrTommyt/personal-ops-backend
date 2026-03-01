package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type N8NClient struct {
	BaseURL      string
	SharedSecret string
	HTTP         *http.Client
}

func NewN8NClient(baseURL, secret string) *N8NClient {
	return &N8NClient{BaseURL: baseURL, SharedSecret: secret, HTTP: &http.Client{Timeout: 8 * time.Second}}
}

func (c *N8NClient) IncidentIngest(ctx context.Context, body any) error {
	if c.BaseURL == "" || c.SharedSecret == "" {
		return nil
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/incident-ingest", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Shared-Secret", c.SharedSecret)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("n8n status %d", resp.StatusCode)
	}
	return nil
}
