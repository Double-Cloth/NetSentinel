CREATE TABLE log_sources (
  id TEXT PRIMARY KEY,
  catalog_id TEXT NOT NULL UNIQUE,
  catalog_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  format TEXT NOT NULL CHECK(format IN ('ssh-rfc3339', 'ssh-rfc3164', 'nginx-combined')),
  year INTEGER NOT NULL DEFAULT 0,
  timezone TEXT NOT NULL DEFAULT '',
  interval_seconds INTEGER NOT NULL CHECK(interval_seconds BETWEEN 30 AND 3600),
  enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
  row_version INTEGER NOT NULL DEFAULT 1,
  generation TEXT NOT NULL DEFAULT '',
  byte_offset INTEGER NOT NULL DEFAULT 0,
  line_no INTEGER NOT NULL DEFAULT 0,
  anchor_hash TEXT NOT NULL DEFAULT '',
  last_success_at INTEGER,
  last_error TEXT NOT NULL DEFAULT '',
  backlog INTEGER NOT NULL DEFAULT 0 CHECK(backlog IN (0, 1)),
  next_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE collection_attempts (
  id TEXT PRIMARY KEY,
  source_id TEXT NOT NULL REFERENCES log_sources(id),
  kind TEXT NOT NULL CHECK(kind IN ('scheduled', 'retry')),
  status TEXT NOT NULL CHECK(status IN ('queued', 'running', 'succeeded', 'failed')),
  phase TEXT NOT NULL DEFAULT '',
  error_code TEXT NOT NULL DEFAULT '',
  error_message TEXT NOT NULL DEFAULT '',
  batch_id TEXT,
  consumed_bytes INTEGER NOT NULL DEFAULT 0,
  valid_lines INTEGER NOT NULL DEFAULT 0,
  ignored_lines INTEGER NOT NULL DEFAULT 0,
  error_lines INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  finished_at INTEGER
);
CREATE INDEX collection_attempts_source ON collection_attempts(source_id, created_at DESC);

CREATE TABLE raw_batches (
  id TEXT PRIMARY KEY,
  source_id TEXT NOT NULL REFERENCES log_sources(id),
  generation TEXT NOT NULL,
  start_offset INTEGER NOT NULL,
  end_offset INTEGER NOT NULL,
  raw_path TEXT NOT NULL UNIQUE,
  raw_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('ready','diagnostic')),
  event_count INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(source_id, generation, start_offset)
);
CREATE INDEX raw_batches_source ON raw_batches(source_id, created_at DESC);

CREATE TABLE raw_lines (
  id TEXT PRIMARY KEY,
  batch_id TEXT NOT NULL REFERENCES raw_batches(id),
  source_id TEXT NOT NULL REFERENCES log_sources(id),
  generation TEXT NOT NULL,
  byte_offset INTEGER NOT NULL,
  line_no INTEGER NOT NULL,
  raw_hash TEXT NOT NULL,
  raw_text TEXT NOT NULL,
  disposition TEXT NOT NULL CHECK(disposition IN ('event', 'ignored', 'error')),
  diagnostic TEXT NOT NULL DEFAULT '',
  UNIQUE(source_id, generation, byte_offset)
);
CREATE INDEX raw_lines_batch ON raw_lines(batch_id, line_no);

CREATE TABLE events (
  id TEXT PRIMARY KEY,
  batch_id TEXT NOT NULL REFERENCES raw_batches(id),
  source_id TEXT NOT NULL REFERENCES log_sources(id),
  event_time_us INTEGER NOT NULL,
  raw_line_id TEXT NOT NULL UNIQUE REFERENCES raw_lines(id),
  payload_json TEXT NOT NULL CHECK(json_valid(payload_json))
);
CREATE INDEX events_source_order ON events(source_id, event_time_us, id);
CREATE INDEX events_batch ON events(batch_id, event_time_us);

CREATE TABLE analysis_tasks (
  id TEXT PRIMARY KEY,
  batch_id TEXT NOT NULL UNIQUE REFERENCES raw_batches(id),
  status TEXT NOT NULL CHECK(status IN ('queued', 'running', 'succeeded', 'failed')),
  error_code TEXT NOT NULL DEFAULT '',
  error_message TEXT NOT NULL DEFAULT '',
  processed_events INTEGER NOT NULL DEFAULT 0,
  new_alerts INTEGER NOT NULL DEFAULT 0,
  reused_alerts INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  finished_at INTEGER
);

CREATE TABLE alerts (
  id TEXT PRIMARY KEY,
  source_id TEXT NOT NULL REFERENCES log_sources(id),
  batch_id TEXT NOT NULL REFERENCES raw_batches(id),
  trigger_event_id TEXT NOT NULL REFERENCES events(id),
  fingerprint TEXT NOT NULL UNIQUE,
  result_digest TEXT NOT NULL,
  finding_json TEXT NOT NULL CHECK(json_valid(finding_json)),
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'closed', 'false_positive')),
  row_version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);
CREATE INDEX alerts_created ON alerts(created_at DESC, id);

CREATE TABLE alert_evidence (
  alert_id TEXT NOT NULL REFERENCES alerts(id),
  ordinal INTEGER NOT NULL,
  event_id TEXT NOT NULL REFERENCES events(id),
  PRIMARY KEY(alert_id, ordinal)
);

CREATE TABLE task_alerts (
  task_id TEXT NOT NULL REFERENCES analysis_tasks(id),
  alert_id TEXT NOT NULL REFERENCES alerts(id),
  PRIMARY KEY(task_id, alert_id)
);
