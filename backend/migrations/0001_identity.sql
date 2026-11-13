CREATE TABLE users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE CHECK(length(username) BETWEEN 3 AND 32 AND username NOT GLOB '*[^a-z0-9_]*'),
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin', 'analyst', 'auditor')),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
  row_version INTEGER NOT NULL DEFAULT 1 CHECK(row_version > 0),
  created_at INTEGER NOT NULL
);

CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE INDEX sessions_expiry ON sessions(expires_at);

CREATE TABLE audit_logs (
  id TEXT PRIMARY KEY,
  actor_id TEXT REFERENCES users(id),
  action TEXT NOT NULL,
  object_type TEXT NOT NULL,
  object_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  change_json TEXT NOT NULL CHECK(json_valid(change_json)),
  result TEXT NOT NULL CHECK(result IN ('success', 'failure', 'denied')),
  created_at INTEGER NOT NULL
);
CREATE INDEX audit_logs_object ON audit_logs(object_type, object_id, created_at, id);
