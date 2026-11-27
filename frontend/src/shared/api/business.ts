import { ApiError } from './client'

export interface Source {
  id: string; catalog_id: string; name: string; format: string; year: number; timezone: string
  interval_seconds: number; enabled: boolean; row_version: number; generation: string
  byte_offset: number; line_no: number; last_success_at: number | null; last_error: string
  next_at: number; health: 'never_collected' | 'disabled' | 'failed' | 'backlog' | 'ready' | 'stale'
}
export interface Alert {
  id: string; source_id: string; batch_id: string; status: string; created_at: number
  finding: { rule_id: string; severity: string; group_values: unknown[]; actual_count: number; threshold: number
    trigger_time_us: number; reason_code: string; evidence: unknown[] }
}
export interface Batch { id: string; source_id: string; generation: string; start_offset: number; end_offset: number; status: 'ready' | 'diagnostic'; event_count: number; created_at: number }
export interface Task { id: string; batch_id: string; status: string; error_code: string; error_message: string; processed_events: number; new_alerts: number; reused_alerts: number; created_at: number }
export interface Attempt { id: string; kind: string; status: string; phase: string; error_code: string; error_message: string; batch_id: string | null; consumed_bytes: number; valid_lines: number; ignored_lines: number; error_lines: number; created_at: number }
export interface Evidence { ordinal: number; event_id: string; event_time_us: number; raw_ref: { file_id: string; line_no: number; raw_hash: string }; raw_text: string }
export interface RawLine { id: string; line_no: number; byte_offset: number; raw_text: string; disposition: string; diagnostic: string }
export interface CatalogEntry { id: string; name: string; format: string }

export async function businessRequest<T>(path: string, options: RequestInit = {}, csrf = ''): Promise<T> {
  const headers = new Headers(options.headers)
  headers.set('Accept', 'application/json')
  if (options.body) headers.set('Content-Type', 'application/json')
  if (csrf) headers.set('X-CSRF-Token', csrf)
  let response: Response
  try { response = await fetch(`/api/v1${path}`, { ...options, credentials: 'same-origin', headers }) }
  catch {
    if (options.signal?.aborted) throw options.signal.reason
    throw new ApiError('无法连接服务，请稍后重试。', 0)
  }
  const body = await response.json().catch(() => null) as { data?: T; error?: { message?: string }; request_id?: string } | null
  if (!response.ok) {
    const message = response.status === 401 ? '会话已失效，请刷新页面后重新登录。' : body?.error?.message ?? '请求失败，请重试。'
    throw new ApiError(message, response.status, body?.request_id)
  }
  if (!body || body.data === undefined) throw new ApiError('服务响应格式无效，请重试。', response.status, body?.request_id)
  return body.data
}

export function timeUS(value: number | null | undefined): string {
  if (value === null || value === undefined) return '尚无记录'
  return new Date(value / 1000).toLocaleString('zh-CN', { hour12: false })
}
