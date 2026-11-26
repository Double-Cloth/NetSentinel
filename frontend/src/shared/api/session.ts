import { ApiError } from './client'

export interface Session {
  user: { id: string; username: string; role: 'admin' | 'analyst' | 'auditor' }
  permissions: string[]
  csrf_token: string
}

export function requestSession(action: 'login' | 'me', options: RequestInit): Promise<Session>
export function requestSession(action: 'logout', options: RequestInit): Promise<void>
export async function requestSession(action: 'login' | 'me' | 'logout', options: RequestInit): Promise<Session | void> {
  const headers = new Headers(options.headers)
  headers.set('Accept', 'application/json')
  let response: Response
  try {
    response = await fetch(`/api/v1/auth/${action}`, { ...options, credentials: 'same-origin', headers })
  } catch {
    if (options.signal?.aborted) throw options.signal.reason
    throw new ApiError('无法连接服务，请重试。', 0)
  }
  if (response.status === 204 && action === 'logout') return
  if (response.status === 401 && action === 'me') throw new ApiError('请先登录。', 401)
  const body = await response.json().catch(() => null) as { data?: Session; error?: { message?: string }; request_id?: string } | null
  if (!response.ok) throw new ApiError(body?.error?.message ?? '认证请求失败，请重试。', response.status, body?.request_id)
  if (!body?.data?.user?.username || !body.data.csrf_token || action === 'logout') {
    throw new ApiError('服务响应格式无效，请重试。', response.status, body?.request_id)
  }
  return body.data
}
