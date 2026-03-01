package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/go-chi/httprate"
	"github.com/google/uuid"

	"personal-ops-backend/internal/auth"
	"personal-ops-backend/internal/config"
	"personal-ops-backend/internal/db"
	"personal-ops-backend/internal/integrations"
	"personal-ops-backend/internal/util"
)

type Server struct {
	cfg   config.Config
	db    *db.DB
	tm    auth.TokenManager
	fcm   *integrations.FCMClient
	n8n   *integrations.N8NClient
	build string
}

func New(cfg config.Config, store *db.DB, fcm *integrations.FCMClient, n8n *integrations.N8NClient, build string) *Server {
	return &Server{
		cfg: cfg,
		db:  store,
		tm: auth.TokenManager{
			AccessSecret:  []byte(cfg.JWTAccessSecret),
			RefreshSecret: []byte(cfg.JWTRefreshSecret),
			AccessTTL:     cfg.JWTAccessTTL,
			RefreshTTL:    cfg.JWTRefreshTTL,
		},
		fcm:   fcm,
		n8n:   n8n,
		build: build,
	}
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(s.requestLogMiddleware)
	r.Use(cors.Handler(cors.Options{AllowedOrigins: []string{}, AllowCredentials: false}))

	r.Get("/health", s.handleHealth)

	r.Group(func(r chi.Router) {
		r.Use(httprate.LimitByIP(5, time.Minute))
		// r.Post("/auth/signup", s.handleSignup)
		r.Post("/auth/login", s.handleLogin)
		r.Post("/auth/refresh", s.handleRefresh)
		r.Post("/auth/logout", s.handleLogout)
	})

	r.Group(func(r chi.Router) {
		r.Use(s.authMiddleware)
		r.Post("/auth/change-password", s.handleChangePassword)
		r.Post("/devices/register", s.handleDeviceRegister)
		r.Post("/devices/unregister", s.handleDeviceUnregister)

		r.Get("/tasks", s.handleTasksList)
		r.Get("/tasks/{id}", s.handleTaskGet)
		r.Get("/tasks/{id}/events", s.handleTaskEvents)
		r.Post("/tasks", s.handleTaskCreate)
		r.Post("/tasks/{id}/action", s.handleTaskAction)
	})

	r.Group(func(r chi.Router) {
		r.Use(httprate.LimitByIP(60, time.Minute))
		r.Post("/webhooks/grafana", s.handleGrafanaWebhook)
		r.Post("/webhooks/n8n-callback", s.handleN8NCallback)
	})

	return r
}

func (s *Server) requestLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		reqID := util.RequestID()
		w.Header().Set("X-Request-Id", reqID)
		next.ServeHTTP(w, r)
		log.Printf("{\"requestId\":\"%s\",\"method\":\"%s\",\"path\":\"%s\",\"durationMs\":%d}", reqID, r.Method, r.URL.Path, time.Since(start).Milliseconds())
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	err := s.db.Health(ctx)
	status := map[string]any{"ok": err == nil, "build": s.build, "time": time.Now().UTC()}
	if err != nil {
		status["error"] = err.Error()
		util.WriteJSON(w, http.StatusServiceUnavailable, status)
		return
	}
	util.WriteJSON(w, http.StatusOK, status)
}

func (s *Server) handleSignup(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.AllowSignup {
		util.WriteJSON(w, http.StatusForbidden, map[string]any{"error": "signup disabled"})
		return
	}
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := util.ReadJSON(r, &in, 1<<20); err != nil {
		util.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	if !validEmail(in.Email) || len(in.Password) < 8 {
		util.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid input"})
		return
	}
	h, err := auth.HashPassword(in.Password, auth.ArgonParams{MemoryKB: s.cfg.PasswordHashMemoryKB, Iter: s.cfg.PasswordHashIter, Parallel: s.cfg.PasswordHashParallel, KeyLen: 32})
	if err != nil {
		util.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "hash failed"})
		return
	}
	u, err := s.db.CreateUser(r.Context(), strings.ToLower(strings.TrimSpace(in.Email)), h)
	if err != nil {
		util.WriteJSON(w, http.StatusConflict, map[string]any{"error": "email already exists"})
		return
	}
	util.WriteJSON(w, http.StatusCreated, map[string]any{"id": u.ID, "email": u.Email, "createdAt": u.CreatedAt})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := util.ReadJSON(r, &in, 1<<20); err != nil {
		util.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	u, err := s.db.GetUserByEmail(r.Context(), strings.ToLower(strings.TrimSpace(in.Email)))
	if err != nil || !auth.VerifyPassword(u.PasswordHash, in.Password) {
		util.WriteJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
		return
	}
	access, err := s.tm.NewAccessToken(u.ID)
	if err != nil {
		util.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "token issue"})
		return
	}
	refresh, err := s.tm.NewRefreshToken(u.ID)
	if err != nil {
		util.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "token issue"})
		return
	}
	if err := s.db.SaveRefreshToken(r.Context(), u.ID, auth.HashOpaque(refresh), time.Now().Add(s.cfg.JWTRefreshTTL)); err != nil {
		util.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "session save failed"})
		return
	}
	_ = s.db.TouchLogin(r.Context(), u.ID)
	util.WriteJSON(w, http.StatusOK, map[string]any{
		"accessToken":        access,
		"refreshToken":       refresh,
		"mustChangePassword": u.MustChangePassword,
		"user": map[string]any{
			"id":                 u.ID,
			"email":              u.Email,
			"isAdmin":            u.IsAdmin,
			"mustChangePassword": u.MustChangePassword,
		},
	})
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RefreshToken string `json:"refreshToken"`
	}
	if err := util.ReadJSON(r, &in, 1<<20); err != nil || in.RefreshToken == "" {
		util.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid input"})
		return
	}
	claims, err := s.tm.ParseRefresh(in.RefreshToken)
	if err != nil {
		util.WriteJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid token"})
		return
	}
	ok, err := s.db.IsValidRefreshToken(r.Context(), claims.UserID, auth.HashOpaque(in.RefreshToken))
	if err != nil || !ok {
		util.WriteJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid token"})
		return
	}
	_ = s.db.RevokeRefreshToken(r.Context(), auth.HashOpaque(in.RefreshToken))
	access, _ := s.tm.NewAccessToken(claims.UserID)
	refresh, _ := s.tm.NewRefreshToken(claims.UserID)
	_ = s.db.SaveRefreshToken(r.Context(), claims.UserID, auth.HashOpaque(refresh), time.Now().Add(s.cfg.JWTRefreshTTL))
	util.WriteJSON(w, http.StatusOK, map[string]any{"accessToken": access, "refreshToken": refresh})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RefreshToken string `json:"refreshToken"`
	}
	_ = util.ReadJSON(r, &in, 1<<20)
	if in.RefreshToken != "" {
		_ = s.db.RevokeRefreshToken(r.Context(), auth.HashOpaque(in.RefreshToken))
	}
	util.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromCtx(r.Context())
	var in struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := util.ReadJSON(r, &in, 1<<20); err != nil {
		util.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	if len(in.NewPassword) < 8 {
		util.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "new password must be at least 8 chars"})
		return
	}
	u, err := s.db.GetUserByID(r.Context(), userID)
	if err == db.ErrNotFound {
		util.WriteJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
		return
	}
	if err != nil || !auth.VerifyPassword(u.PasswordHash, in.CurrentPassword) {
		util.WriteJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
		return
	}
	if auth.VerifyPassword(u.PasswordHash, in.NewPassword) {
		util.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "new password must be different"})
		return
	}
	newHash, err := auth.HashPassword(in.NewPassword, auth.ArgonParams{
		MemoryKB: s.cfg.PasswordHashMemoryKB,
		Iter:     s.cfg.PasswordHashIter,
		Parallel: s.cfg.PasswordHashParallel,
		KeyLen:   32,
	})
	if err != nil {
		util.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "hash failed"})
		return
	}
	if err := s.db.ChangeUserPassword(r.Context(), userID, newHash); err != nil {
		util.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "password update failed"})
		return
	}
	_ = s.db.RevokeAllRefreshTokensForUser(r.Context(), userID)
	util.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleDeviceRegister(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromCtx(r.Context())
	var in struct {
		Platform string `json:"platform"`
		FCMToken string `json:"fcmToken"`
	}
	if err := util.ReadJSON(r, &in, 1<<20); err != nil {
		util.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	if in.Platform != "ios" || strings.TrimSpace(in.FCMToken) == "" {
		util.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid input"})
		return
	}
	dev, err := s.db.UpsertDevice(r.Context(), userID, in.Platform, in.FCMToken)
	if err != nil {
		util.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "device register failed"})
		return
	}
	util.WriteJSON(w, http.StatusOK, dev)
}

func (s *Server) handleDeviceUnregister(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromCtx(r.Context())
	var in struct {
		FCMToken string `json:"fcmToken"`
	}
	if err := util.ReadJSON(r, &in, 1<<20); err != nil || in.FCMToken == "" {
		util.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid input"})
		return
	}
	_ = s.db.RemoveDevice(r.Context(), userID, in.FCMToken)
	util.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleTasksList(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromCtx(r.Context())
	status := r.URL.Query().Get("status")
	typ := r.URL.Query().Get("type")
	cursor, err := util.ParseCursorRFC3339(r.URL.Query().Get("cursor"))
	if err != nil {
		util.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid cursor"})
		return
	}
	tasks, err := s.db.ListTasks(r.Context(), userID, status, typ, 25, cursor)
	if err != nil {
		util.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
		return
	}
	nextCursor := ""
	if len(tasks) > 0 {
		nextCursor = tasks[len(tasks)-1].UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	util.WriteJSON(w, http.StatusOK, map[string]any{"items": tasks, "nextCursor": nextCursor})
}

func (s *Server) handleTaskGet(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromCtx(r.Context())
	t, err := s.db.GetTask(r.Context(), chi.URLParam(r, "id"), userID)
	if err == db.ErrNotFound {
		util.WriteJSON(w, http.StatusNotFound, map[string]any{"error": "task not found"})
		return
	}
	if err != nil {
		util.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
		return
	}
	util.WriteJSON(w, http.StatusOK, t)
}

func (s *Server) handleTaskEvents(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromCtx(r.Context())
	id := chi.URLParam(r, "id")
	if _, err := s.db.GetTask(r.Context(), id, userID); err == db.ErrNotFound {
		util.WriteJSON(w, http.StatusNotFound, map[string]any{"error": "task not found"})
		return
	} else if err != nil {
		util.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
		return
	}
	events, err := s.db.ListTaskEvents(r.Context(), id)
	if err != nil {
		util.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
		return
	}
	util.WriteJSON(w, http.StatusOK, map[string]any{"items": events})
}

func (s *Server) handleTaskCreate(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromCtx(r.Context())
	var in struct {
		Type     string          `json:"type"`
		Title    string          `json:"title"`
		Status   string          `json:"status"`
		Severity *string         `json:"severity"`
		Payload  json.RawMessage `json:"payload"`
	}
	if err := util.ReadJSON(r, &in, 1<<20); err != nil || in.Type == "" || in.Title == "" {
		util.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid input"})
		return
	}
	if in.Status == "" {
		in.Status = "open"
	}
	source := "manual"
	t, err := s.db.CreateTask(r.Context(), db.Task{UserID: userID, Type: in.Type, Title: in.Title, Status: in.Status, Severity: in.Severity, Source: &source, Payload: in.Payload})
	if err != nil {
		util.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "create failed"})
		return
	}
	_, _ = s.db.AddTaskEvent(r.Context(), t.ID, "user:"+userID, "created", in.Payload)
	_ = s.enqueuePush(r.Context(), userID, t.ID, "New task", t.Title)
	_ = s.enqueueN8N(r.Context(), t)
	util.WriteJSON(w, http.StatusCreated, t)
}

func (s *Server) handleTaskAction(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromCtx(r.Context())
	taskID := chi.URLParam(r, "id")
	if _, err := s.db.GetTask(r.Context(), taskID, userID); err == db.ErrNotFound {
		util.WriteJSON(w, http.StatusNotFound, map[string]any{"error": "task not found"})
		return
	} else if err != nil {
		util.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
		return
	}
	var in struct {
		Action string          `json:"action"`
		Note   string          `json:"note"`
		Fields json.RawMessage `json:"fields"`
	}
	if err := util.ReadJSON(r, &in, 1<<20); err != nil || in.Action == "" {
		util.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid input"})
		return
	}
	idk := r.Header.Get("Idempotency-Key")
	scope := fmt.Sprintf("task_action:%s:%s", userID, taskID)
	if idk != "" {
		var cached map[string]any
		hit, _ := s.db.GetIdempotency(r.Context(), scope, idk, &cached)
		if hit {
			util.WriteJSON(w, http.StatusOK, cached)
			return
		}
	}
	status := mapActionToStatus(in.Action)
	if status == "" {
		util.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported action"})
		return
	}
	if err := s.db.UpdateTaskStatus(r.Context(), taskID, status); err != nil {
		util.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "update failed"})
		return
	}
	eventData, _ := json.Marshal(map[string]any{"action": in.Action, "note": in.Note, "fields": json.RawMessage(in.Fields)})
	_, _ = s.db.AddTaskEvent(r.Context(), taskID, "user:"+userID, "action", eventData)
	resp := map[string]any{"ok": true, "taskId": taskID, "status": status}
	if idk != "" {
		_ = s.db.SaveIdempotency(r.Context(), scope, idk, resp)
	}
	_ = s.enqueuePush(r.Context(), userID, taskID, "Task updated", strings.ToUpper(status))
	util.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGrafanaWebhook(w http.ResponseWriter, r *http.Request) {
	secret := r.Header.Get("X-Grafana-Token")
	body, err := util.ReadBody(r, 2<<20)
	if err != nil {
		util.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid body"})
		return
	}
	if secret == "" && !util.VerifyHMACSHA256Hex(body, s.cfg.GrafanaWebhookSecret, r.Header.Get("X-Grafana-Signature")) {
		util.WriteJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid signature"})
		return
	}
	if secret != "" && secret != s.cfg.GrafanaWebhookSecret {
		util.WriteJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid token"})
		return
	}
	var in struct {
		Alerts []struct {
			Status      string                 `json:"status"`
			Labels      map[string]string      `json:"labels"`
			RuleUID     string                 `json:"ruleUid"`
			RuleName    string                 `json:"ruleName"`
			Annotations map[string]string      `json:"annotations"`
			Raw         map[string]interface{} `json:"-"`
		} `json:"alerts"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		util.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	user, err := s.pickSingleUser(r.Context())
	if err != nil {
		util.WriteJSON(w, http.StatusAccepted, map[string]any{"ok": true})
		return
	}
	for _, a := range in.Alerts {
		dk := grafanaDedupe(a.RuleUID, a.Labels)
		title := a.RuleName
		if title == "" {
			title = "Grafana incident"
		}
		payload, _ := json.Marshal(a)
		if strings.EqualFold(a.Status, "resolved") {
			t, err := s.db.FindOpenTaskByDedupe(r.Context(), user.ID, dk)
			if err == nil {
				_ = s.db.UpdateTaskStatus(r.Context(), t.ID, "resolved")
				_, _ = s.db.AddTaskEvent(r.Context(), t.ID, "grafana", "status_changed", []byte(`{"status":"resolved"}`))
				_ = s.enqueuePush(r.Context(), user.ID, t.ID, "Incident resolved", title)
			}
			continue
		}
		t, err := s.db.FindOpenTaskByDedupe(r.Context(), user.ID, dk)
		if err == db.ErrNotFound {
			source := "grafana"
			t, err = s.db.CreateTask(r.Context(), db.Task{UserID: user.ID, Type: "incident", Title: title, Status: "open", Source: &source, DedupeKey: &dk, Payload: payload})
			if err == nil {
				_, _ = s.db.AddTaskEvent(r.Context(), t.ID, "grafana", "created", payload)
				_ = s.enqueuePush(r.Context(), user.ID, t.ID, "Incident firing", title)
				_ = s.enqueueN8N(r.Context(), t)
			}
		} else if err == nil {
			_ = s.db.TouchTask(r.Context(), t.ID, payload)
			_, _ = s.db.AddTaskEvent(r.Context(), t.ID, "grafana", "status_changed", []byte(`{"status":"open"}`))
		}
	}
	util.WriteJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

func (s *Server) handleN8NCallback(w http.ResponseWriter, r *http.Request) {
	body, err := util.ReadBody(r, 1<<20)
	if err != nil {
		util.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid body"})
		return
	}
	sig := r.Header.Get("X-N8N-Signature")
	if !util.VerifyHMACSHA256Hex(body, s.cfg.N8NCallbackSecret, sig) {
		util.WriteJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid signature"})
		return
	}
	var in struct {
		TaskID string `json:"taskId"`
		Patch  struct {
			Title        *string        `json:"title"`
			Severity     *string        `json:"severity"`
			PayloadMerge map[string]any `json:"payloadMerge"`
		} `json:"patch"`
		Event map[string]any `json:"event"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.TaskID == "" {
		util.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid payload"})
		return
	}
	merge, _ := json.Marshal(in.Patch.PayloadMerge)
	if err := s.db.PatchTaskFromN8N(r.Context(), in.TaskID, in.Patch.Title, in.Patch.Severity, merge); err != nil {
		util.WriteJSON(w, http.StatusInternalServerError, map[string]any{"error": "patch failed"})
		return
	}
	ev, _ := json.Marshal(in.Event)
	_, _ = s.db.AddTaskEvent(r.Context(), in.TaskID, "n8n", "enriched", ev)
	util.WriteJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

func (s *Server) enqueuePush(ctx context.Context, userID, taskID, title, body string) error {
	pl, _ := json.Marshal(map[string]string{"userId": userID, "taskId": taskID, "title": title, "body": body})
	return s.db.Enqueue(ctx, "push", pl)
}

func (s *Server) enqueueN8N(ctx context.Context, t db.Task) error {
	pl, _ := json.Marshal(map[string]any{"taskId": t.ID, "type": t.Type, "status": t.Status, "payloadNormalized": json.RawMessage(t.Payload)})
	return s.db.Enqueue(ctx, "n8n_call", pl)
}

func mapActionToStatus(action string) string {
	switch strings.ToLower(action) {
	case "ack", "acknowledge":
		return "acknowledged"
	case "resolve":
		return "resolved"
	case "approve":
		return "approved"
	case "reject":
		return "rejected"
	case "submit":
		return "submitted"
	case "close":
		return "closed"
	default:
		return ""
	}
}

func validEmail(e string) bool { return strings.Contains(e, "@") && len(e) <= 255 }

func grafanaDedupe(ruleUID string, labels map[string]string) string {
	if labels == nil {
		labels = map[string]string{}
	}
	b, _ := json.Marshal(labels)
	h := sha256.Sum256(b)
	return ruleUID + ":" + hex.EncodeToString(h[:8])
}

func (s *Server) pickSingleUser(ctx context.Context) (db.User, error) {
	row := s.db.Pool.QueryRow(ctx, `
select id,email,password_hash,is_admin,must_change_password,created_at,last_login_at,password_changed_at
from users order by created_at asc limit 1
`)
	var u db.User
	err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.IsAdmin, &u.MustChangePassword, &u.CreatedAt, &u.LastLoginAt, &u.PasswordChangedAt)
	return u, err
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		parts := strings.SplitN(authz, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			util.WriteJSON(w, http.StatusUnauthorized, map[string]any{"error": "missing token"})
			return
		}
		claims, err := s.tm.ParseAccess(parts[1])
		if err != nil {
			util.WriteJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid token"})
			return
		}
		next.ServeHTTP(w, r.WithContext(withUserID(r.Context(), claims.UserID)))
	})
}

type ctxKey string

const userIDKey ctxKey = "uid"

func withUserID(ctx context.Context, uid string) context.Context {
	return context.WithValue(ctx, userIDKey, uid)
}

func userIDFromCtx(ctx context.Context) string {
	v, _ := ctx.Value(userIDKey).(string)
	if v == "" {
		return uuid.Nil.String()
	}
	return v
}
