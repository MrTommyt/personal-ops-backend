alter table users add column if not exists is_admin boolean not null default false;
alter table users add column if not exists must_change_password boolean not null default false;
alter table users add column if not exists password_changed_at timestamptz;

create index if not exists idx_users_is_admin on users(is_admin);
