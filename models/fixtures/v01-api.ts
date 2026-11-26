// 本文件定义评审用 HTTP 契约。实际服务及客户端接入由后续工作包实现。

export type UTCMicros = `${string}Z`
export type SHA256 = string
export type Role = 'admin' | 'analyst' | 'auditor'
export type Severity = 'low' | 'medium' | 'high' | 'critical'

export type Success<T> = { data: T; request_id: string; error?: never }
export type Failure = {
  error: {
    code: string
    message: string
    details?: { path: string; message: string }[]
  }
  request_id: string
  data?: never
}
export type Response<T> = Success<T> | Failure
export type Page<T> = { items: T[]; page: number; page_size: number; total: number }

type ParserConfig =
  | { format: 'ssh-rfc3164'; timezone: string; year: number }
  | { format: 'ssh-rfc3339' | 'nginx-combined'; timezone?: never; year?: never }

export type LogSourceCreate = ParserConfig & {
  source_ref: string
  name: string
  enabled: boolean
  interval_seconds: number
}
export type LogSourceUpdate = Omit<LogSourceCreate, 'source_ref' | 'format' | 'timezone' | 'year'> &
  ParserConfig & { row_version: number }

export type CollectionPhase = 'authorize' | 'connect' | 'pull' | 'parse' | 'persist' | 'commit'
export type CollectionCode =
  | 'SOURCE_CONFIG_INVALID'
  | 'SOURCE_UNREACHABLE'
  | 'SOURCE_HOST_KEY_MISMATCH'
  | 'SOURCE_AUTH_FAILED'
  | 'SOURCE_GENERATION_CHANGED'
  | 'SOURCE_CURSOR_MISMATCH'
  | 'SOURCE_LINE_TOO_LONG'
  | 'SOURCE_RESOURCE_LIMIT'
  | 'SOURCE_STORAGE_FAILED'
  | 'SOURCE_COMMIT_FAILED'
  | 'SOURCE_INTERRUPTED'

type CollectionError = { phase: CollectionPhase; code: CollectionCode; message: string }

export type LogSource = ParserConfig & {
  id: string
  name: string
  enabled: boolean
  interval_seconds: number
  health: 'uncollected' | 'healthy' | 'backlogged' | 'failed' | 'disabled'
  last_success_at: UTCMicros | null
  next_collection_at: UTCMicros | null
  last_error: CollectionError | null
  row_version: number
}

export type SubmitCollection = { row_version: number }
export type CollectionAccepted = { attempt_id: string }
export type CollectionAttempt = {
  id: string
  source_id: string
  source_row_version: number
  kind: 'scheduled' | 'retry' | 'test'
  status: 'queued' | 'running' | 'succeeded' | 'failed'
  phase: CollectionPhase | null
  created_at: UTCMicros
  finished_at: UTCMicros | null
  consumed_bytes: number
  valid_lines: number
  ignored_lines: number
  error_lines: number
  batch_id: string | null
  error: CollectionError | null
  preview?: { line_no: number; status: 'valid' | 'ignored' | 'invalid'; code?: string }[]
}

export type RawRef = { file_id: string; line_no: number; raw_hash: SHA256 }

type EventCommon = {
  schema_version: 1
  event_id: string
  event_index: number
  dataset_id: string
  event_time: UTCMicros
  source_host: string
  src_ip: string
  raw_ref: RawRef
}
export type Event = EventCommon & (
  | {
    source: 'ssh'
    kind: 'ssh.auth_failed' | 'ssh.auth_success'
    user: { name: string }
    ssh?: { invalid_user?: boolean; auth_method?: string }
  }
  | {
    source: 'nginx'
    kind: 'http.access'
    http: { method: string; path: string; status: number; bytes_sent?: number }
  }
)

type Predicate =
  | { all: Predicate[] }
  | { any: Predicate[] }
  | { field: string; op: 'eq' | 'neq' | 'gt' | 'gte' | 'lt' | 'lte' | 'prefix' | 'regex'; value: string | number | boolean }

export type CountRuleSpec = {
  schema_version: 1
  rule_id: string
  name: string
  description?: string
  source: Event['source']
  type: 'count'
  severity: Severity
  group_by: string[]
  window_seconds: number
  where: Predicate
  threshold: number
}
export type RuleValidation = { rule_id: string; spec_hash: SHA256; engine_semantics_version: '1.0.0' }
export type RuleVersionRef = { rule_id: string; version: number; spec_hash: SHA256 }
export type TaskSnapshot = {
  dataset_id: string
  dataset_digest: SHA256
  rules: RuleVersionRef[]
  engine_semantics_version: '1.0.0'
}
export type AnalysisTask = {
  id: string
  trigger: 'automatic' | 'manual' | 'rerun'
  status: 'queued' | 'running' | 'committing' | 'succeeded' | 'failed'
  phase: 'input' | 'detect' | 'commit' | null
  snapshot: TaskSnapshot
  processed_events: number
  total_events: number
  new_alerts: number
  reused_alerts: number
  error: { code: string; message: string } | null
}

export type Alert = {
  id: string
  dataset_id: string
  rule_id: string
  rule_version: number
  severity: Severity
  status: 'open' | 'acknowledged' | 'closed' | 'false_positive'
  assignee: string | null
  row_version: number
  group_fields: string[]
  group_values: (string | number)[]
  window_start: UTCMicros
  window_end: UTCMicros
  actual_count: number
  threshold: number
  reason_code: 'COUNT_THRESHOLD_ENTERED'
}
export type Evidence = {
  ordinal: number
  event_id: string
  event_index: number
  event_time: UTCMicros
  raw_ref: RawRef
}

export type V01Examples = {
  log_source: Success<LogSource>
  retry_accepted: Success<CollectionAccepted>
  collection_attempt: Success<CollectionAttempt>
  task: Success<AnalysisTask>
  alert: Success<Alert>
  alert_evidence: Success<Page<Evidence>>
  invalid_source: Failure
  stale_source: Failure
}
