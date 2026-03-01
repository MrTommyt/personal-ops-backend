package db

import "time"

type User struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	PasswordHash string    `json:"-"`
	CreatedAt   time.Time  `json:"createdAt"`
	LastLoginAt *time.Time `json:"lastLoginAt,omitempty"`
}

type Device struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userId"`
	Platform  string    `json:"platform"`
	FCMToken  string    `json:"-"`
	CreatedAt time.Time `json:"createdAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
}

type Task struct {
	ID             string    `json:"id"`
	UserID         string    `json:"userId"`
	Type           string    `json:"type"`
	Title          string    `json:"title"`
	Status         string    `json:"status"`
	Severity       *string   `json:"severity,omitempty"`
	Source         *string   `json:"source,omitempty"`
	DedupeKey      *string   `json:"dedupeKey,omitempty"`
	Payload        []byte    `json:"payload"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
	AcknowledgedAt *time.Time `json:"acknowledgedAt,omitempty"`
	ResolvedAt     *time.Time `json:"resolvedAt,omitempty"`
}

type TaskEvent struct {
	ID        string    `json:"id"`
	TaskID    string    `json:"taskId"`
	Actor     string    `json:"actor"`
	EventType string    `json:"eventType"`
	Data      []byte    `json:"data"`
	CreatedAt time.Time `json:"createdAt"`
}
