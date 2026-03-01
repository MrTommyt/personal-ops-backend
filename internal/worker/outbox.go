package worker

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"personal-ops-backend/internal/db"
	"personal-ops-backend/internal/integrations"
)

type OutboxWorker struct {
	DB  *db.DB
	FCM *integrations.FCMClient
	N8N *integrations.N8NClient
}

func (w *OutboxWorker) Start(ctx context.Context) {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.tick(ctx)
		}
	}
}

func (w *OutboxWorker) tick(ctx context.Context) {
	items, err := w.DB.PullOutbox(ctx, 20)
	if err != nil {
		log.Printf("outbox pull error: %v", err)
		return
	}
	for _, item := range items {
		if err := w.handle(ctx, item); err != nil {
			_ = w.DB.NackOutbox(ctx, item.ID, item.Attempts+1, err.Error())
			continue
		}
		_ = w.DB.AckOutbox(ctx, item.ID)
	}
}

func (w *OutboxWorker) handle(ctx context.Context, item db.OutboxItem) error {
	switch item.Kind {
	case "push":
		var in struct {
			UserID string `json:"userId"`
			TaskID string `json:"taskId"`
			Title  string `json:"title"`
			Body   string `json:"body"`
		}
		if err := json.Unmarshal(item.Payload, &in); err != nil {
			return err
		}
		tokens, err := w.DB.ListDeviceTokens(ctx, in.UserID)
		if err != nil {
			return err
		}
		for _, tok := range tokens {
			err := w.FCM.Send(ctx, tok, in.Title, in.Body, map[string]string{"taskId": in.TaskID})
			if err != nil && err.Error() == "invalid_token" {
				_ = w.DB.RemoveDeviceByToken(ctx, tok)
				continue
			}
			if err != nil {
				return err
			}
		}
		return nil
	case "n8n_call":
		var in map[string]any
		if err := json.Unmarshal(item.Payload, &in); err != nil {
			return err
		}
		return w.N8N.IncidentIngest(ctx, in)
	default:
		return errors.New("unsupported outbox kind")
	}
}
