# Backend Plan.md — Personal Ops (Railway) + n8n + Grafana

## Goal
Deploy a secure backend on Railway that supports:
- Email/password auth for a single user (personal ops)
- Task Inbox API for iOS app (incidents, approvals, forms, feedback)
- Grafana alert ingestion (webhook) → task creation + updates
- Push notifications to iPhone (via FCM HTTP v1)
- n8n integration (backend triggers workflows; n8n can callback backend)
- Offline/action queue friendly semantics (idempotent actions, audit log)

Non-goals (v1):
- Multi-user RBAC / org features
- Full on-call rotation
- Complex incident paging systems (PagerDuty, OpsGenie) unless added later

---

## High-level Architecture (Railway)
### Services
1) **api** (Node.js / Fastify or NestJS; alternatively Go)
2) **postgres** (Railway Postgres)
3) **n8n** (separate Railway service)
4) **vector store** (optional later for RAG: Qdrant or pgvector)

### Network boundaries
- Public:
  - `api` (public HTTPS)
  - `n8n` (public only if required; ideally restricted)
- Private/controlled access:
  - `n8n` webhooks called only by `api` using a shared secret
  - `api` callbacks from `n8n` validated with signature/secret
  - Grafana webhook authenticated (HMAC signature or secret header)

### Data ownership
- Backend (`api` + Postgres) is the source of truth for tasks, users, devices, audit logs.
- n8n orchestrates and enriches but should not be the primary data store.

---

## Deployment on Railway
### Railway projects
- Single Railway project with multiple services is fine (api + postgres + n8n).
- Add custom domains:
  - `api.yourdomain.com` → api
  - `n8n.yourdomain.com` → n8n (optional)

### Required environment variables (api)
- `DATABASE_URL` (from Railway Postgres)
- `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`
- `JWT_ACCESS_TTL_SECONDS=900` (example 15m)
- `JWT_REFRESH_TTL_DAYS=30`
- `PASSWORD_HASH_COST` (bcrypt/argon2 settings)
- `GRAFANA_WEBHOOK_SECRET` (shared secret)
- `N8N_WEBHOOK_BASE_URL` (e.g., `https://n8n.yourdomain.com/webhook`)
- `N8N_SHARED_SECRET` (for backend → n8n)
- `N8N_CALLBACK_SECRET` (for n8n → backend)
- `FCM_PROJECT_ID`
- `FCM_CLIENT_EMAIL`
- `FCM_PRIVATE_KEY` (store as Railway secret; careful with newlines)
- `FCM_ENABLED=true`
- `BASE_URL=https://api.yourdomain.com`

### Required environment variables (n8n)
- n8n DB settings (Postgres)
- `N8N_ENCRYPTION_KEY`
- `WEBHOOK_URL=https://n8n.yourdomain.com`

---

## Backend tech choices
### Recommended stack (fast to build)
- Node 20+ + Fastify (or NestJS if you prefer structure)
- Postgres + migrations (Prisma / Drizzle / Knex)
- Zod for request validation
- BullMQ or simple DB-backed job table for async push sends
  - For personal ops, start with in-process queue + retry; evolve later.

---

## Database Schema (v1)
### users
- `id uuid pk`
- `email citext unique`
- `password_hash text`
- `created_at timestamptz`
- `last_login_at timestamptz`

### refresh_tokens
- `id uuid pk`
- `user_id uuid fk`
- `token_hash text` (store hash, not plaintext)
- `created_at timestamptz`
- `expires_at timestamptz`
- `revoked_at timestamptz null`
- `device_id uuid null`

### devices
- `id uuid pk`
- `user_id uuid fk`
- `platform text` (`ios`)
- `fcm_token text unique`
- `created_at timestamptz`
- `last_seen_at timestamptz`

### tasks
- `id uuid pk`
- `type text` (`incident|approval|form|feedback`)
- `title text`
- `status text` (`open|acknowledged|resolved|approved|rejected|submitted|closed`)
- `severity text null` (`info|warning|critical`)
- `source text null` (`grafana|manual|n8n`)
- `dedupe_key text null` (unique partial index for open incidents)
- `payload jsonb` (raw alert/form schema/form answers/etc.)
- `created_at timestamptz`
- `updated_at timestamptz`
- `acknowledged_at timestamptz null`
- `resolved_at timestamptz null`

### task_events (audit log)
- `id uuid pk`
- `task_id uuid fk`
- `actor text` (`user:<id>|system|grafana|n8n`)
- `event_type text` (`created|status_changed|note_added|action|enriched`)
- `data jsonb`
- `created_at timestamptz`

### outbox (optional but recommended)
Use if you want reliable push delivery & workflow calls:
- `id uuid pk`
- `kind text` (`push|n8n_call`)
- `payload jsonb`
- `attempts int`
- `next_attempt_at timestamptz`
- `last_error text null`
- `created_at timestamptz`

Indexes:
- `tasks(status, updated_at desc)`
- `tasks(type, status)`
- `tasks(dedupe_key)` unique where `status in ('open','acknowledged')` (incidents)
- `devices(user_id)`
- `task_events(task_id, created_at desc)`

---

## API Design (v1)
### Auth
- `POST /auth/signup` (optional; can seed user manually)
- `POST /auth/login` {email,password} → {accessToken, refreshToken, user}
- `POST /auth/refresh` {refreshToken} → {accessToken, refreshToken}
- `POST /auth/logout` {refreshToken} (revoke)

Rules:
- Rate limit login attempts
- Always respond with generic errors for invalid credentials
- Store refresh tokens hashed; rotate on refresh

### Devices
- `POST /devices/register` (auth required)
  - body: `{ platform:"ios", fcmToken:"..." }`
- `POST /devices/unregister` (auth required)

### Tasks
- `GET /tasks?status=open&type=incident&cursor=...`
- `GET /tasks/:id`
- `GET /tasks/:id/events`
- `POST /tasks` (auth required for manual creation; internal for system)
- `POST /tasks/:id/action` (auth required)
  - body: `{ action, note?, fields? }`

Action behavior:
- Idempotency: accept `Idempotency-Key` header; store per action to prevent duplicates.
- Create a `task_events` row for every action.
- Update task status timestamps.

### Webhooks
- `POST /webhooks/grafana`
  - Auth: `X-Grafana-Token: <secret>` OR HMAC signature
- `POST /webhooks/n8n-callback`
  - Auth: `X-N8N-Signature` (HMAC of body with callback secret)

Response codes:
- Always return 2xx quickly; heavy work should be queued via outbox.

---

## Grafana Ingestion Logic (Incidents)
Input: Grafana webhook payload containing alerts with state transitions.

Algorithm:
1) Validate signature/secret header.
2) For each alert:
   - Build `dedupe_key = ruleUid + ':' + hash(labels)` (stable)
   - If state is firing:
     - Upsert task with status `open` (or keep acknowledged if already ack’d)
     - Title: derive from rule name + key labels
     - Payload: store full alert payload + a normalized subset
     - Emit `task_event: created` or `status_changed`
     - Enqueue push notification
     - Optionally enqueue n8n enrichment call
   - If state is resolved:
     - Find open/ack task by `dedupe_key`
     - Set status `resolved`, timestamps, event log
     - Enqueue push “resolved” notification

Dedupe rules:
- Multiple identical firing alerts should not create multiple tasks; update `updated_at` + add event.

---

## Push Notifications (FCM HTTP v1)
Strategy:
- Backend sends push to all registered devices for the user.
- Minimal notification payload (avoid leaking sensitive data on lock screen):
  - title: short
  - body: short
  - data: `{ taskId }`

Delivery:
- Implement `sendPush(taskId, title, body)` with retry:
  - If token invalid → remove device row
  - Retry transient errors with exponential backoff (outbox)

---

## n8n Integration
### Backend → n8n
When:
- New incident created
- Action taken (ack/resolve)
- Manual task created

How:
- `POST {N8N_WEBHOOK_BASE_URL}/incident-ingest`
- Headers: `X-Shared-Secret: {N8N_SHARED_SECRET}`
- Body: `{ taskId, type, status, payloadNormalized }`

### n8n → Backend callback
Use for enrichment or automation results:
- `POST /webhooks/n8n-callback`
- Headers: `X-N8N-Signature: hmac_sha256(body, N8N_CALLBACK_SECRET)`
- Body example:
  - `{ taskId, patch: { title?, severity?, payloadMerge?, tags? }, event: {...} }`

Backend applies patch (whitelisted fields only), writes `task_event: enriched`, updates `updated_at`, and optionally sends a push.

Security rules:
- Never allow n8n callbacks to arbitrarily modify auth/devices.
- Task patch is validated and field-limited.

---

## Security Checklist (v1)
- HTTPS only (Railway provides)
- JWT access token short TTL + refresh rotation
- Password hashing: argon2id preferred, bcrypt acceptable
- Rate limit:
  - `/auth/login`
  - `/webhooks/grafana` (basic)
- Webhook authentication:
  - Grafana secret header or HMAC
  - n8n callback signature
- Strict CORS (mobile apps don’t need permissive CORS; restrict to none or minimal)
- Validate all inputs (Zod)
- Avoid storing secrets in logs
- Database least privilege user (Railway default is usually ok; avoid superuser actions in app code)

---

## Observability & Ops
- Structured logs (JSON) with request id
- Health endpoint: `GET /health` (db connectivity + build info)
- Metrics (optional):
  - counts of created incidents, push success/fail, webhook errors
- Alerts:
  - if webhook failures spike
  - if push outbox backlog grows

---

## Milestones / Work Packages
### WP1 — Foundation (1–2 days)
- Project scaffold, config, DB migrations
- Auth endpoints + JWT + refresh tokens
- Basic tasks CRUD + events table

### WP2 — Grafana webhook (1–2 days)
- Webhook endpoint + validation
- Dedupe/upsert logic
- Task events + status transitions

### WP3 — Push delivery (1–3 days)
- Devices registration endpoints
- FCM HTTP v1 sender
- Outbox/retry (at least in-process; DB outbox preferred)

### WP4 — n8n integration (1–2 days)
- Backend → n8n webhook calls
- n8n → backend callback verification + patch apply
- Event logging + optional push on enrichment

### WP5 — Hardening (1–3 days)
- Rate limiting
- Idempotency keys for task actions
- Better pagination and filtering
- Audit log completeness
- Cleanup of invalid FCM tokens

Definition of done:
- iOS app can login, fetch tasks, action tasks
- Grafana alerts create/update tasks
- Push notifications arrive reliably
- n8n can enrich tasks via callback without security issues

---

## Notes on “Personal Ops” simplifications
- Single-user: you can either allow signup or seed a single account and disable signup in prod.
- No RBAC needed; all tasks belong to the user.
- A single device initially; keep multi-device support anyway (easy).

---

## Deliverables from backend agent
- Railway-deployable repo (Dockerfile or Railway buildpack)
- Migration scripts + schema
- OpenAPI spec (or Postman collection) for all endpoints
- Local dev instructions (docker-compose for postgres optional)
- Basic test suite (auth + webhook + task actions)
- Runbook for rotating secrets and FCM credentials
