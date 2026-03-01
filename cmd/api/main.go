package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"personal-ops-backend/internal/auth"
	"personal-ops-backend/internal/config"
	"personal-ops-backend/internal/db"
	"personal-ops-backend/internal/httpapi"
	"personal-ops-backend/internal/integrations"
	"personal-ops-backend/internal/worker"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	store, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	if err := store.Migrate(ctx, "migrations"); err != nil {
		log.Fatal(err)
	}
	if err := ensureDefaultAdmin(ctx, store, cfg); err != nil {
		log.Fatal(err)
	}

	fcm := integrations.NewFCMClient(cfg.FCMEnabled, cfg.FCMProjectID, cfg.FCMClientEmail, cfg.FCMPrivateKey)
	n8n := integrations.NewN8NClient(cfg.N8NWebhookBaseURL, cfg.N8NSharedSecret)
	srv := httpapi.New(cfg, store, fcm, n8n, getBuild())

	workerCtx, workerCancel := context.WithCancel(ctx)
	ow := &worker.OutboxWorker{DB: store, FCM: fcm, N8N: n8n}
	go ow.Start(workerCtx)

	httpSrv := &http.Server{Addr: cfg.Addr, Handler: srv.Router(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Printf("api listening on %s", cfg.Addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	<-quit
	workerCancel()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
}

func getBuild() string {
	if v := os.Getenv("BUILD_SHA"); v != "" {
		return v
	}
	return "dev"
}

func ensureDefaultAdmin(ctx context.Context, store *db.DB, cfg config.Config) error {
	email := strings.ToLower(strings.TrimSpace(cfg.DefaultAdminEmail))
	if email == "" || cfg.DefaultAdminPassword == "" {
		return nil
	}
	hash, err := auth.HashPassword(cfg.DefaultAdminPassword, auth.ArgonParams{
		MemoryKB: cfg.PasswordHashMemoryKB,
		Iter:     cfg.PasswordHashIter,
		Parallel: cfg.PasswordHashParallel,
		KeyLen:   32,
	})
	if err != nil {
		return err
	}
	return store.EnsureDefaultAdmin(ctx, email, hash)
}
