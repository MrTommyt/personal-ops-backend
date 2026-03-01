# Personal Ops Backend (Go)

Go implementation of the API described in `Plan.md`, optimized for low resource usage on Railway.

## Features
- Email/password auth with JWT access + refresh rotation
- Device registration for iOS FCM tokens
- Task inbox API + task events audit log
- Idempotent task actions via `Idempotency-Key`
- Grafana webhook ingestion with dedupe and status transitions
- n8n callback verification and task enrichment
- DB-backed outbox worker for push + n8n retries

## Run locally
1. Start Postgres and create a DB.
2. Copy `.env.example` values into your environment.
3. Run:
```bash
go mod tidy
go run ./cmd/api
```

## Railway deploy
- Use included `Dockerfile`.
- Provide required env vars listed in `.env.example` and `Plan.md`.

## API docs
- OpenAPI: `docs/openapi.yaml`

## Tests
```bash
go test ./...
```
