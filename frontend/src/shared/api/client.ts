export interface Health {
  status: 'ok' | 'unavailable'
  checks: Record<'api' | 'database' | 'directory', 'ready' | 'unavailable'>
  engine_semantics_version: string
}

export class ApiError extends Error {
  constructor(message: string, public readonly status: number, public readonly requestId?: string) {
    super(message)
    this.name = 'ApiError'
  }
}

export async function fetchHealth(signal: AbortSignal): Promise<Health> {
  let response: Response
  try {
    response = await fetch('/api/v1/health/ready', {
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
      signal,
    })
  } catch {
    if (signal.aborted) throw signal.reason
    throw new ApiError('无法连接服务，请确认后端已启动后重试。', 0)
  }
  let payload: unknown
  try {
    payload = await response.json()
  } catch {
    throw new ApiError('服务响应格式无效，请重新检查。', response.status)
  }
  if (!payload || typeof payload !== 'object') throw new ApiError('服务响应格式无效，请重新检查。', response.status)
  const body = payload as { data?: Partial<Health>; error?: { message?: string }; request_id?: string }
  if (!response.ok && response.status !== 503) {
    throw new ApiError(body.error?.message ?? '服务检查失败，请稍后重试。', response.status, body.request_id)
  }
  const health = body.data
  if (!health || !['ok', 'unavailable'].includes(health.status ?? '') ||
      typeof health.engine_semantics_version !== 'string' ||
      !['api', 'database', 'directory'].every(key => ['ready', 'unavailable'].includes(health.checks?.[key as keyof Health['checks']] ?? ''))) {
    throw new ApiError('服务响应格式无效，请重新检查。', response.status, body.request_id)
  }
  return health as Health
}
