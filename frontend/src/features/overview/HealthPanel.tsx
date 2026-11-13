import { useEffect, useRef, useState } from 'react'
import { fetchHealth, type Health } from '../../shared/api/client'

const checks = [
  ['api', 'API 服务'],
  ['database', 'SQLite 存储'],
  ['directory', '运行目录'],
] as const

export function HealthPanel() {
  const [health, setHealth] = useState<Health | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [attempt, setAttempt] = useState(0)
  const controller = useRef<AbortController | null>(null)

  useEffect(() => {
    const current = new AbortController()
    controller.current = current
    const timeout = window.setTimeout(() => current.abort(new Error('服务检查超时，请重新检查。')), 6000)
    fetchHealth(current.signal).then(result => {
      if (!current.signal.aborted) setHealth(result)
    }).catch((cause: unknown) => {
      if (controller.current !== current) return
      setError(cause instanceof Error ? cause.message : '无法连接服务，请确认后端已启动。')
    }).finally(() => {
      window.clearTimeout(timeout)
      if (controller.current === current) setLoading(false)
    })
    return () => {
      controller.current = null
      window.clearTimeout(timeout)
      current.abort()
    }
  }, [attempt])

  function refresh() {
    setLoading(true)
    setError('')
    setHealth(null)
    setAttempt(value => value + 1)
  }

  return (
    <section className="panel" aria-labelledby="health-heading" aria-busy={loading}>
      <div className="section-heading">
        <h2 id="health-heading">服务状态</h2>
        <button type="button" onClick={refresh} disabled={loading}>{loading ? '检查中…' : '重新检查'}</button>
      </div>
      <div aria-live="polite">
        {error ? <p className="error-message" role="alert">{error}</p> : null}
        <dl className="health-list">
          {checks.map(([key, label]) => {
            let status = '等待检查'
            if (loading) status = '检查中…'
            else if (health) status = health.checks[key] === 'ready' ? '就绪' : '不可用'
            else if (error) status = '连接失败'
            return <div key={key}><dt>{label}</dt><dd className={health?.checks[key] === 'ready' ? 'ready' : ''}>{status}</dd></div>
          })}
        </dl>
        {health?.status === 'unavailable' ? <p className="error-message">部分检查未通过，请检查后端运行环境后重试。</p> : null}
      </div>
    </section>
  )
}
