import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, fetchHealth } from './client'

afterEach(() => vi.unstubAllGlobals())

describe('健康检查 API', () => {
  it.each([200, 503])('解析 HTTP %s 的真实检查项', async status => {
    const health = { status: status === 200 ? 'ok' : 'unavailable', checks: { api: 'ready', database: status === 200 ? 'ready' : 'unavailable', directory: 'ready' }, engine_semantics_version: '1.0.0' }
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ data: health, request_id: 'request-1' }), { status })))
    await expect(fetchHealth(new AbortController().signal)).resolves.toEqual(health)
  })

  it('保留服务错误和请求标识', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { message: '检查失败' }, request_id: 'request-1' }), { status: 500 })))
    await expect(fetchHealth(new AbortController().signal)).rejects.toMatchObject({ message: '检查失败', status: 500, requestId: 'request-1' })
  })

  it('拒绝缺少检查项的响应', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ data: { status: 'ok' } }))))
    await expect(fetchHealth(new AbortController().signal)).rejects.toBeInstanceOf(ApiError)
  })

  it('将连接失败转为中文恢复提示', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')))
    await expect(fetchHealth(new AbortController().signal)).rejects.toMatchObject({ message: '无法连接服务，请确认后端已启动后重试。', status: 0 })
  })

  it('拒绝返回 HTML 的代理响应', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('<html>upstream error</html>', { status: 502 })))
    await expect(fetchHealth(new AbortController().signal)).rejects.toMatchObject({ message: '服务响应格式无效，请重新检查。', status: 502 })
  })
})
