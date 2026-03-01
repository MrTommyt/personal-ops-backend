create extension if not exists citext;

create table if not exists users (
  id uuid primary key,
  email citext unique not null,
  password_hash text not null,
  created_at timestamptz not null default now(),
  last_login_at timestamptz
);

create table if not exists refresh_tokens (
  id uuid primary key,
  user_id uuid not null references users(id) on delete cascade,
  token_hash text not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_at timestamptz,
  device_id uuid
);

create table if not exists devices (
  id uuid primary key,
  user_id uuid not null references users(id) on delete cascade,
  platform text not null,
  fcm_token text unique not null,
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now()
);

create table if not exists tasks (
  id uuid primary key,
  user_id uuid not null references users(id) on delete cascade,
  type text not null,
  title text not null,
  status text not null,
  severity text,
  source text,
  dedupe_key text,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  acknowledged_at timestamptz,
  resolved_at timestamptz
);

create table if not exists task_events (
  id uuid primary key,
  task_id uuid not null references tasks(id) on delete cascade,
  actor text not null,
  event_type text not null,
  data jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists outbox (
  id uuid primary key,
  kind text not null,
  payload jsonb not null,
  attempts int not null default 0,
  next_attempt_at timestamptz not null default now(),
  last_error text,
  created_at timestamptz not null default now()
);

create table if not exists idempotency_keys (
  id uuid primary key,
  scope text not null,
  key text not null,
  response jsonb not null,
  created_at timestamptz not null default now(),
  unique(scope, key)
);

create index if not exists idx_tasks_status_updated on tasks(status, updated_at desc);
create index if not exists idx_tasks_type_status on tasks(type, status);
create unique index if not exists idx_tasks_dedupe_open on tasks(dedupe_key) where status in ('open','acknowledged');
create index if not exists idx_devices_user_id on devices(user_id);
create index if not exists idx_task_events_task_id_created on task_events(task_id, created_at desc);
create index if not exists idx_outbox_schedule on outbox(next_attempt_at, attempts);
