package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrNotFound = errors.New("not found")

func (d *DB) CreateUser(ctx context.Context, email, passwordHash string) (User, error) {
	u := User{ID: uuid.NewString(), Email: email, PasswordHash: passwordHash, IsAdmin: false, MustChangePassword: false}
	err := d.Pool.QueryRow(ctx, `
insert into users(id,email,password_hash,is_admin,must_change_password,password_changed_at)
values($1,$2,$3,$4,$5,now())
returning created_at
`, u.ID, u.Email, u.PasswordHash, u.IsAdmin, u.MustChangePassword).Scan(&u.CreatedAt)
	return u, err
}

func (d *DB) GetUserByEmail(ctx context.Context, email string) (User, error) {
	var u User
	err := d.Pool.QueryRow(ctx, `
select id,email,password_hash,is_admin,must_change_password,created_at,last_login_at,password_changed_at
from users where email=$1
`, email).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.IsAdmin, &u.MustChangePassword, &u.CreatedAt, &u.LastLoginAt, &u.PasswordChangedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

func (d *DB) GetUserByID(ctx context.Context, userID string) (User, error) {
	var u User
	err := d.Pool.QueryRow(ctx, `
select id,email,password_hash,is_admin,must_change_password,created_at,last_login_at,password_changed_at
from users where id=$1
`, userID).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.IsAdmin, &u.MustChangePassword, &u.CreatedAt, &u.LastLoginAt, &u.PasswordChangedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

func (d *DB) TouchLogin(ctx context.Context, userID string) error {
	_, err := d.Pool.Exec(ctx, `update users set last_login_at=now() where id=$1`, userID)
	return err
}

func (d *DB) EnsureDefaultAdmin(ctx context.Context, email, passwordHash string) error {
	_, err := d.Pool.Exec(ctx, `
insert into users(id,email,password_hash,is_admin,must_change_password)
values($1,$2,$3,true,true)
on conflict (email) do nothing
`, uuid.NewString(), email, passwordHash)
	return err
}

func (d *DB) ChangeUserPassword(ctx context.Context, userID, newPasswordHash string) error {
	_, err := d.Pool.Exec(ctx, `
update users
set password_hash=$2, must_change_password=false, password_changed_at=now()
where id=$1
`, userID, newPasswordHash)
	return err
}

func (d *DB) RevokeAllRefreshTokensForUser(ctx context.Context, userID string) error {
	_, err := d.Pool.Exec(ctx, `update refresh_tokens set revoked_at=now() where user_id=$1 and revoked_at is null`, userID)
	return err
}

func (d *DB) SaveRefreshToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	_, err := d.Pool.Exec(ctx, `insert into refresh_tokens(id,user_id,token_hash,expires_at) values($1,$2,$3,$4)`, uuid.NewString(), userID, tokenHash, expiresAt)
	return err
}

func (d *DB) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	_, err := d.Pool.Exec(ctx, `update refresh_tokens set revoked_at=now() where token_hash=$1 and revoked_at is null`, tokenHash)
	return err
}

func (d *DB) IsValidRefreshToken(ctx context.Context, userID, tokenHash string) (bool, error) {
	var ok bool
	err := d.Pool.QueryRow(ctx, `select exists(select 1 from refresh_tokens where user_id=$1 and token_hash=$2 and revoked_at is null and expires_at>now())`, userID, tokenHash).Scan(&ok)
	return ok, err
}

func (d *DB) UpsertDevice(ctx context.Context, userID, platform, fcmToken string) (Device, error) {
	dev := Device{ID: uuid.NewString(), UserID: userID, Platform: platform, FCMToken: fcmToken}
	err := d.Pool.QueryRow(ctx, `
insert into devices(id,user_id,platform,fcm_token)
values($1,$2,$3,$4)
on conflict (fcm_token) do update set user_id=excluded.user_id, platform=excluded.platform, last_seen_at=now()
returning id,user_id,platform,created_at,last_seen_at
`, dev.ID, dev.UserID, dev.Platform, dev.FCMToken).Scan(&dev.ID, &dev.UserID, &dev.Platform, &dev.CreatedAt, &dev.LastSeenAt)
	return dev, err
}

func (d *DB) RemoveDevice(ctx context.Context, userID, fcmToken string) error {
	_, err := d.Pool.Exec(ctx, `delete from devices where user_id=$1 and fcm_token=$2`, userID, fcmToken)
	return err
}

func (d *DB) RemoveDeviceByToken(ctx context.Context, fcmToken string) error {
	_, err := d.Pool.Exec(ctx, `delete from devices where fcm_token=$1`, fcmToken)
	return err
}

func (d *DB) ListDeviceTokens(ctx context.Context, userID string) ([]string, error) {
	rows, err := d.Pool.Query(ctx, `select fcm_token from devices where user_id=$1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]string, 0, 4)
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (d *DB) CreateTask(ctx context.Context, t Task) (Task, error) {
	if t.ID == "" {
		t.ID = uuid.NewString()
	}
	if len(t.Payload) == 0 {
		t.Payload = []byte(`{}`)
	}
	err := d.Pool.QueryRow(ctx, `
insert into tasks(id,user_id,type,title,status,severity,source,dedupe_key,payload)
values($1,$2,$3,$4,$5,$6,$7,$8,$9)
returning created_at,updated_at
`, t.ID, t.UserID, t.Type, t.Title, t.Status, t.Severity, t.Source, t.DedupeKey, t.Payload).Scan(&t.CreatedAt, &t.UpdatedAt)
	return t, err
}

func (d *DB) GetTask(ctx context.Context, taskID, userID string) (Task, error) {
	var t Task
	err := d.Pool.QueryRow(ctx, `
select id,user_id,type,title,status,severity,source,dedupe_key,payload,created_at,updated_at,acknowledged_at,resolved_at
from tasks where id=$1 and user_id=$2
`, taskID, userID).Scan(&t.ID, &t.UserID, &t.Type, &t.Title, &t.Status, &t.Severity, &t.Source, &t.DedupeKey, &t.Payload, &t.CreatedAt, &t.UpdatedAt, &t.AcknowledgedAt, &t.ResolvedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, ErrNotFound
	}
	return t, err
}

func (d *DB) ListTasks(ctx context.Context, userID, status, typ string, limit int, cursor *time.Time) ([]Task, error) {
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	query := `select id,user_id,type,title,status,severity,source,dedupe_key,payload,created_at,updated_at,acknowledged_at,resolved_at from tasks where user_id=$1`
	args := []any{userID}
	idx := 2
	if status != "" {
		query += fmt.Sprintf(" and status=$%d", idx)
		args = append(args, status)
		idx++
	}
	if typ != "" {
		query += fmt.Sprintf(" and type=$%d", idx)
		args = append(args, typ)
		idx++
	}
	if cursor != nil {
		query += fmt.Sprintf(" and updated_at < $%d", idx)
		args = append(args, *cursor)
		idx++
	}
	query += " order by updated_at desc limit " + fmt.Sprintf("%d", limit)

	rows, err := d.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Task, 0, limit)
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.UserID, &t.Type, &t.Title, &t.Status, &t.Severity, &t.Source, &t.DedupeKey, &t.Payload, &t.CreatedAt, &t.UpdatedAt, &t.AcknowledgedAt, &t.ResolvedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (d *DB) AddTaskEvent(ctx context.Context, taskID, actor, eventType string, data []byte) (TaskEvent, error) {
	e := TaskEvent{ID: uuid.NewString(), TaskID: taskID, Actor: actor, EventType: eventType, Data: data}
	if len(e.Data) == 0 {
		e.Data = []byte(`{}`)
	}
	err := d.Pool.QueryRow(ctx, `insert into task_events(id,task_id,actor,event_type,data) values($1,$2,$3,$4,$5) returning created_at`, e.ID, e.TaskID, e.Actor, e.EventType, e.Data).Scan(&e.CreatedAt)
	return e, err
}

func (d *DB) ListTaskEvents(ctx context.Context, taskID string) ([]TaskEvent, error) {
	rows, err := d.Pool.Query(ctx, `select id,task_id,actor,event_type,data,created_at from task_events where task_id=$1 order by created_at desc`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TaskEvent
	for rows.Next() {
		var e TaskEvent
		if err := rows.Scan(&e.ID, &e.TaskID, &e.Actor, &e.EventType, &e.Data, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (d *DB) UpdateTaskStatus(ctx context.Context, taskID, status string) error {
	_, err := d.Pool.Exec(ctx, `
update tasks set status=$2, updated_at=now(),
acknowledged_at = case when $2='acknowledged' then coalesce(acknowledged_at, now()) else acknowledged_at end,
resolved_at = case when $2 in ('resolved','closed') then coalesce(resolved_at, now()) else resolved_at end
where id=$1
`, taskID, status)
	return err
}

func (d *DB) SaveIdempotency(ctx context.Context, scope, key string, response any) error {
	b, err := json.Marshal(response)
	if err != nil {
		return err
	}
	_, err = d.Pool.Exec(ctx, `insert into idempotency_keys(id,scope,key,response) values($1,$2,$3,$4) on conflict (scope,key) do nothing`, uuid.NewString(), scope, key, b)
	return err
}

func (d *DB) GetIdempotency(ctx context.Context, scope, key string, dest any) (bool, error) {
	var b []byte
	err := d.Pool.QueryRow(ctx, `select response from idempotency_keys where scope=$1 and key=$2`, scope, key).Scan(&b)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(b, dest)
}

func (d *DB) Enqueue(ctx context.Context, kind string, payload []byte) error {
	_, err := d.Pool.Exec(ctx, `insert into outbox(id,kind,payload) values($1,$2,$3)`, uuid.NewString(), kind, payload)
	return err
}

type OutboxItem struct {
	ID       string
	Kind     string
	Payload  []byte
	Attempts int
}

func (d *DB) PullOutbox(ctx context.Context, limit int) ([]OutboxItem, error) {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
select id,kind,payload,attempts
from outbox
where next_attempt_at <= now() and attempts < 10
order by created_at asc
for update skip locked
limit $1
`, limit)
	if err != nil {
		return nil, err
	}
	var out []OutboxItem
	for rows.Next() {
		var i OutboxItem
		if err := rows.Scan(&i.ID, &i.Kind, &i.Payload, &i.Attempts); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, i)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, nil
	}
	ids := make([]string, 0, len(out))
	for _, i := range out {
		ids = append(ids, i.ID)
	}
	if _, err := tx.Exec(ctx, `update outbox set attempts=attempts+1 where id = any($1)`, ids); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

func (d *DB) AckOutbox(ctx context.Context, id string) error {
	_, err := d.Pool.Exec(ctx, `delete from outbox where id=$1`, id)
	return err
}

func (d *DB) NackOutbox(ctx context.Context, id string, attempts int, lastErr string) error {
	backoff := time.Duration(1<<min(attempts, 6)) * time.Minute
	_, err := d.Pool.Exec(ctx, `update outbox set next_attempt_at=now()+$2::interval, last_error=$3 where id=$1`, id, fmt.Sprintf("%d seconds", int(backoff.Seconds())), truncate(lastErr, 500))
	return err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (d *DB) FindOpenTaskByDedupe(ctx context.Context, userID, dedupeKey string) (Task, error) {
	var t Task
	err := d.Pool.QueryRow(ctx, `
select id,user_id,type,title,status,severity,source,dedupe_key,payload,created_at,updated_at,acknowledged_at,resolved_at
from tasks where user_id=$1 and dedupe_key=$2 and status in ('open','acknowledged')
`, userID, dedupeKey).Scan(&t.ID, &t.UserID, &t.Type, &t.Title, &t.Status, &t.Severity, &t.Source, &t.DedupeKey, &t.Payload, &t.CreatedAt, &t.UpdatedAt, &t.AcknowledgedAt, &t.ResolvedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, ErrNotFound
	}
	return t, err
}

func (d *DB) TouchTask(ctx context.Context, taskID string, payload []byte) error {
	_, err := d.Pool.Exec(ctx, `update tasks set updated_at=now(), payload = payload || $2::jsonb where id=$1`, taskID, payload)
	return err
}

func (d *DB) PatchTaskFromN8N(ctx context.Context, taskID string, title *string, severity *string, payloadMerge []byte) error {
	if len(payloadMerge) == 0 {
		payloadMerge = []byte(`{}`)
	}
	_, err := d.Pool.Exec(ctx, `
update tasks
set title=coalesce($2, title),
    severity=coalesce($3, severity),
    payload=payload || $4::jsonb,
    updated_at=now()
where id=$1
`, taskID, title, severity, payloadMerge)
	return err
}
