package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr                 string
	DatabaseURL          string
	JWTAccessSecret      string
	JWTRefreshSecret     string
	JWTAccessTTL         time.Duration
	JWTRefreshTTL        time.Duration
	PasswordHashMemoryKB uint32
	PasswordHashIter     uint32
	PasswordHashParallel uint8
	GrafanaWebhookSecret string
	N8NWebhookBaseURL    string
	N8NSharedSecret      string
	N8NCallbackSecret    string
	FCMProjectID         string
	FCMClientEmail       string
	FCMPrivateKey        string
	FCMEnabled           bool
	BaseURL              string
	AllowSignup          bool
	DefaultAdminEmail    string
	DefaultAdminPassword string
}

func Load() (Config, error) {
	var cfg Config
	cfg.Addr = getDefault("ADDR", ":8080")
	cfg.DatabaseURL = os.Getenv("DATABASE_URL")
	cfg.JWTAccessSecret = os.Getenv("JWT_ACCESS_SECRET")
	cfg.JWTRefreshSecret = os.Getenv("JWT_REFRESH_SECRET")

	accessTTLSeconds := getDefaultInt("JWT_ACCESS_TTL_SECONDS", 900)
	cfg.JWTAccessTTL = time.Duration(accessTTLSeconds) * time.Second

	refreshTTLDays := getDefaultInt("JWT_REFRESH_TTL_DAYS", 30)
	cfg.JWTRefreshTTL = time.Duration(refreshTTLDays) * 24 * time.Hour

	cfg.PasswordHashMemoryKB = uint32(getDefaultInt("PASSWORD_HASH_MEMORY_KB", 64*1024))
	cfg.PasswordHashIter = uint32(getDefaultInt("PASSWORD_HASH_ITER", 2))
	cfg.PasswordHashParallel = uint8(getDefaultInt("PASSWORD_HASH_PARALLEL", 1))

	cfg.GrafanaWebhookSecret = os.Getenv("GRAFANA_WEBHOOK_SECRET")
	cfg.N8NWebhookBaseURL = strings.TrimRight(os.Getenv("N8N_WEBHOOK_BASE_URL"), "/")
	cfg.N8NSharedSecret = os.Getenv("N8N_SHARED_SECRET")
	cfg.N8NCallbackSecret = os.Getenv("N8N_CALLBACK_SECRET")

	cfg.FCMProjectID = os.Getenv("FCM_PROJECT_ID")
	cfg.FCMClientEmail = os.Getenv("FCM_CLIENT_EMAIL")
	cfg.FCMPrivateKey = strings.ReplaceAll(os.Getenv("FCM_PRIVATE_KEY"), `\\n`, "\n")
	cfg.FCMEnabled = strings.EqualFold(getDefault("FCM_ENABLED", "false"), "true")
	cfg.BaseURL = getDefault("BASE_URL", "http://localhost:8080")
	cfg.AllowSignup = strings.EqualFold(getDefault("ALLOW_SIGNUP", "true"), "true")
	cfg.DefaultAdminEmail = strings.ToLower(strings.TrimSpace(getDefault("DEFAULT_ADMIN_EMAIL", "admin@local.dev")))
	cfg.DefaultAdminPassword = getDefault("DEFAULT_ADMIN_PASSWORD", "ChangeMe123!")

	if cfg.DatabaseURL == "" || cfg.JWTAccessSecret == "" || cfg.JWTRefreshSecret == "" {
		return cfg, fmt.Errorf("missing required env vars: DATABASE_URL/JWT_ACCESS_SECRET/JWT_REFRESH_SECRET")
	}
	return cfg, nil
}

func getDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getDefaultInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
	}
	return fallback
}
