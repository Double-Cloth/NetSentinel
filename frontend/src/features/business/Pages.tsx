import { useEffect, useState, type FormEvent } from 'react'
import type { Session } from '../../shared/api/session'
import { businessRequest, timeUS, type Alert, type Attempt, type Batch, type CatalogEntry, type Evidence, type RawLine, type Source, type Task } from '../../shared/api/business'

function useItems<T>(path: string, refresh = 0, poll = false) {
  const [items, setItems] = useState<T[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [revision, setRevision] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    const load = () => businessRequest<{ items: T[] }>(path, { signal: controller.signal }).then(value => {
      if (!controller.signal.aborted) { setItems(value.items); setError(''); setLoading(false) }
    }).catch((cause: unknown) => {
      if (!controller.signal.aborted) { setError(cause instanceof Error ? cause.message : '请求失败'); setLoading(false) }
    })
    void load()
    const timer = poll ? window.setInterval(() => { void load() }, 5000) : 0
    return () => { controller.abort(); if (timer) window.clearInterval(timer) }
  }, [path, refresh, revision, poll])
  return { items, error, loading, reload: () => setRevision(value => value + 1) }
}

function State({ loading, error, retry }: { loading: boolean; error: string; retry: () => void }) {
  return <>{loading && <p role="status">正在加载…</p>}{error && <p className="error-message" role="alert">{error} <button type="button" onClick={retry}>重试</button></p>}</>
}

const healthName: Record<string, string> = { ready: '正常', failed: '采集失败', backlog: '存在积压', stale: '数据已过期', never_collected: '尚未采集', disabled: '已停用' }
const taskStatusName: Record<string, string> = { queued: '排队中', running: '分析中', succeeded: '已完成', failed: '失败' }
const attemptStatusName: Record<string, string> = { queued: '排队中', running: '采集中', succeeded: '已完成', failed: '失败' }
const alertStatusName: Record<string, string> = { open: '待处理', closed: '已关闭', false_positive: '误报' }

export function Overview() {
  const alerts = useItems<Alert>('/alerts', 0, true)
  const sources = useItems<Source>('/log-sources', 0, true)
  return <>
    <section className="panel"><h2>最近告警</h2><State loading={alerts.loading} error={alerts.error} retry={alerts.reload} />
      {!alerts.loading && !alerts.error && alerts.items.length === 0 && <p>尚无告警。请核对来源采集状态；无数据不代表没有风险。</p>}
      {alerts.items.slice(0, 8).map(alert => <div className="record" key={alert.id}>
        <div><strong>{alert.finding.rule_id}</strong> · {alert.finding.severity} · {alertStatusName[alert.status] ?? alert.status}</div>
        <div>{alert.finding.group_values.join(' / ')} · {alert.finding.actual_count} 次 · {timeUS(alert.finding.trigger_time_us)}</div>
        <a href={`/alerts/${alert.id}`}>查看证据</a>
      </div>)}<a href="/alerts">查看全部告警</a>
    </section>
    <section className="panel"><h2>日志源状态</h2><State loading={sources.loading} error={sources.error} retry={sources.reload} />
      {!sources.loading && !sources.error && sources.items.length === 0 && <p>尚未配置授权日志源。管理员可在系统设置中启用部署者提供的来源。</p>}
      {sources.items.map(source => <div className="record" key={source.id}>
        <strong>{source.name}</strong> · {healthName[source.health] ?? source.health}
        <div>最近成功：{timeUS(source.last_success_at)} · 下次计划：{timeUS(source.next_at)}</div>
        {source.last_error && <p className="error-message">{source.last_error}</p>}
        <a href="/settings">查看来源及恢复操作</a>
      </div>)}
    </section>
  </>
}

export function Sources({ session }: { session: Session }) {
  const sourceData = useItems<Source>('/log-sources', 0, true)
  const [catalog, setCatalog] = useState<CatalogEntry[]>([])
  const [selected, setSelected] = useState('')
  const [interval, setIntervalSeconds] = useState(60)
  const [year, setYear] = useState(new Date().getFullYear())
  const [timezone, setTimezone] = useState('Asia/Shanghai')
  const [message, setMessage] = useState('')
  const [pending, setPending] = useState(false)
  const admin = session.user.role === 'admin'
  useEffect(() => {
    if (!admin) return
    const controller = new AbortController()
    businessRequest<{ items: CatalogEntry[] }>('/log-sources/catalog', { signal: controller.signal }).then(value => {
      if (!controller.signal.aborted) { setCatalog(value.items); setMessage('') }
    }).catch(() => { if (!controller.signal.aborted) setMessage('授权源目录加载失败，请重试。') })
    return () => controller.abort()
  }, [admin])
  const chosen = catalog.find(item => item.id === selected)
  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!selected || pending) return
    setPending(true); setMessage('')
    try {
      await businessRequest('/log-sources', { method: 'POST', body: JSON.stringify({ source_ref: selected, interval_seconds: interval,
        year: chosen?.format === 'ssh-rfc3164' ? year : 0, timezone: chosen?.format === 'ssh-rfc3164' ? timezone : '', enabled: true }) }, session.csrf_token)
      sourceData.reload(); setMessage('来源已启用，调度器即将尝试采集。')
    } catch (cause) { setMessage(cause instanceof Error ? cause.message : '创建失败') }
    finally { setPending(false) }
  }
  async function update(source: Source, enabled: boolean) {
    setMessage('')
    try { await businessRequest(`/log-sources/${source.id}`, { method: 'PATCH', body: JSON.stringify({ source_ref: source.catalog_id,
      interval_seconds: source.interval_seconds, year: source.year, timezone: source.timezone, enabled, row_version: source.row_version }) }, session.csrf_token)
      sourceData.reload() } catch (cause) { setMessage(cause instanceof Error ? cause.message : '更新失败') }
  }
  async function retry(source: Source) {
    setMessage('')
    try { await businessRequest(`/log-sources/${source.id}/retry`, { method: 'POST' }, session.csrf_token); sourceData.reload(); setMessage('已提交重试，请查看采集记录。') }
    catch (cause) { setMessage(cause instanceof Error ? cause.message : '重试失败') }
  }
  async function test(source: Source) {
    setMessage('')
    try {
      const preview = await businessRequest<{ status: string; lines: { disposition: string }[] }>(`/log-sources/${source.id}/test`, { method: 'POST' }, session.csrf_token)
      setMessage(`连接测试通过：预览 ${preview.lines.length} 行，有效 ${preview.lines.filter(line => line.disposition === 'event').length} 行。断点未改变。`)
    } catch (cause) { setMessage(cause instanceof Error ? cause.message : '连接测试失败') }
  }
  return <>
    <section className="panel"><h2>授权日志源</h2><State loading={sourceData.loading} error={sourceData.error} retry={sourceData.reload} />
      {message && <p role="status" className={message.includes('失败') || message.includes('冲突') ? 'error-message' : 'stage-note'}>{message}</p>}
      {!sourceData.loading && !sourceData.error && sourceData.items.length === 0 && <p>尚未配置来源。</p>}
      {sourceData.items.map(source => <SourceCard key={source.id} source={source} admin={admin} onUpdate={update} onRetry={retry} onTest={test} />)}
    </section>
    {admin && <section className="panel"><h2>启用部署者授权的来源</h2>
      {catalog.length === 0 ? <p>授权源目录为空。请先由部署者配置只读连接。</p> :
        <form className="source-form" onSubmit={create}>
          <label htmlFor="source-ref">来源</label><select id="source-ref" required value={selected} onChange={event => setSelected(event.target.value)}>
            <option value="">请选择授权来源</option>{catalog.map(entry => <option key={entry.id} value={entry.id}>{entry.name}（{entry.format}）</option>)}
          </select>
          <label htmlFor="interval">采集周期（秒，30—3600）</label><input id="interval" type="number" min="30" max="3600" value={interval} onChange={event => setIntervalSeconds(Number(event.target.value))} />
          {chosen?.format === 'ssh-rfc3164' && <><label htmlFor="year">日志年份</label><input id="year" type="number" min="1" max="9999" value={year} onChange={event => setYear(Number(event.target.value))} />
            <label htmlFor="timezone">IANA 时区</label><input id="timezone" value={timezone} onChange={event => setTimezone(event.target.value)} /></>}
          <button type="submit" disabled={pending || !selected}>{pending ? '提交中…' : '启用来源'}</button>
        </form>}
    </section>}
  </>
}

function SourceCard({ source, admin, onUpdate, onRetry, onTest }: { source: Source; admin: boolean; onUpdate: (source: Source, enabled: boolean) => void; onRetry: (source: Source) => void; onTest: (source: Source) => void }) {
  const attempts = useItems<Attempt>(`/log-sources/${source.id}/attempts`, 0, true)
  return <div className="record"><h3>{source.name}</h3><p>{source.format} · {healthName[source.health] ?? source.health} · 每 {source.interval_seconds} 秒</p>
    <p>最近成功：{timeUS(source.last_success_at)} · 下次计划：{timeUS(source.next_at)} · 已消费 {source.byte_offset} 字节</p>
    {source.last_error && <p className="error-message">{source.last_error}</p>}
    {admin && <div className="actions"><button type="button" onClick={() => onTest(source)}>连接测试</button><button type="button" onClick={() => onUpdate(source, !source.enabled)}>{source.enabled ? '停用' : '启用'}</button>
      {source.enabled && <button type="button" onClick={() => onRetry(source)}>立即重试</button>}</div>}
    <h4>最近采集</h4><State loading={attempts.loading} error={attempts.error} retry={attempts.reload} />
    {attempts.items.slice(0, 5).map(item => <p key={item.id}>{timeUS(item.created_at)} · {attemptStatusName[item.status] ?? item.status} · 有效 {item.valid_lines} 行 / 错误 {item.error_lines} 行
      {item.error_message && <span className="error-message"> · {item.error_code}：{item.error_message}</span>}{item.batch_id && <> · <a href={`/datasets/${item.batch_id}`}>查看批次</a></>}</p>)}
  </div>
}

export function Datasets({ id }: { id?: string }) {
  const batches = useItems<Batch>('/datasets')
  const lines = useItems<RawLine>(id ? `/datasets/${id}/lines` : '/datasets', 0)
  return <section className="panel"><h2>不可变采集批次</h2><State loading={batches.loading} error={batches.error} retry={batches.reload} />
    {id ? <><a href="/datasets">返回批次列表</a><h3>原始行与解析诊断</h3><State loading={lines.loading} error={lines.error} retry={lines.reload} />
      {lines.items.map(line => <div className="record" key={line.id}><strong>第 {line.line_no} 行 · {line.disposition}</strong> {line.diagnostic}
        <pre>{line.raw_text}</pre></div>)}</> : <>{!batches.loading && !batches.error && batches.items.length === 0 && <p>尚无已采集批次，请查看来源状态。</p>}
      {batches.items.map(batch => <div className="record" key={batch.id}><strong>{batch.source_id}</strong> · {batch.status === 'ready' ? '就绪' : '仅诊断'} · {batch.event_count} 个事件 · {timeUS(batch.created_at)}
        <p>代次 {batch.generation} · 字节区间 [{batch.start_offset}, {batch.end_offset})</p><a href={`/datasets/${batch.id}`}>查看原始行</a></div>)}</>}
  </section>
}

export function Tasks({ session }: { session: Session }) {
  const data = useItems<Task>('/tasks', 0, true)
  const [message, setMessage] = useState('')
  async function retry(id: string) {
    try { await businessRequest(`/tasks/${id}/retry`, { method: 'POST' }, session.csrf_token); setMessage('分析任务已重新排队。'); data.reload() }
    catch (cause) { setMessage(cause instanceof Error ? cause.message : '重试失败') }
  }
  return <section className="panel"><h2>自动分析任务</h2><State loading={data.loading} error={data.error} retry={data.reload} />{message && <p role="status">{message}</p>}
    {!data.loading && !data.error && data.items.length === 0 && <p>尚无分析任务；SSH 批次就绪后会自动创建。</p>}
    {data.items.map(task => <div className="record" key={task.id}><strong>{taskStatusName[task.status] ?? task.status}</strong> · {timeUS(task.created_at)} · 输入事件 {task.processed_events}
      <p>批次 <a href={`/datasets/${task.batch_id}`}>{task.batch_id.slice(0, 16)}…</a> · 新告警 {task.new_alerts} / 复用 {task.reused_alerts}</p>
      {task.error_code && <p className="error-message">{task.error_code}：{task.error_message}</p>}
      {task.status === 'failed' && session.user.role !== 'auditor' && <button type="button" onClick={() => void retry(task.id)}>重试分析</button>}</div>)}
  </section>
}

export function Alerts({ id }: { id?: string }) {
  const list = useItems<Alert>('/alerts', 0, true)
  const evidence = useItems<Evidence>(id ? `/alerts/${id}/evidence` : '/alerts')
  const alert = list.items.find(item => item.id === id)
  return <section className="panel"><h2>站内告警与证据</h2><State loading={list.loading} error={list.error} retry={list.reload} />
    {id ? <><a href="/alerts">返回告警列表</a>{alert && <div className="record"><h3>{alert.finding.rule_id} · {alertStatusName[alert.status] ?? alert.status}</h3>
      <p>分组：{alert.finding.group_values.join(' / ')} · 窗口命中 {alert.finding.actual_count} 次（阈值 {alert.finding.threshold}）</p>
      <p>触发时间：{timeUS(alert.finding.trigger_time_us)} · 原因：{alert.finding.reason_code}</p></div>}
      <h3>证据时间线</h3><State loading={evidence.loading} error={evidence.error} retry={evidence.reload} />
      {evidence.items.map(item => <div className="record" key={item.ordinal}><strong>#{item.ordinal} · {timeUS(item.event_time_us)}</strong>
        <p>原始行 {item.raw_ref.line_no} · SHA-256 {item.raw_ref.raw_hash}</p><pre>{item.raw_text}</pre></div>)}
    </> : <>{!list.loading && !list.error && list.items.length === 0 && <p>尚无告警。请同时查看来源是否离线或积压。</p>}
      {list.items.map(item => <div className="record" key={item.id}><strong>{item.finding.rule_id}</strong> · {item.finding.severity} · {alertStatusName[item.status] ?? item.status} · {timeUS(item.finding.trigger_time_us)}
        <p>{item.finding.group_values.join(' / ')} · {item.finding.actual_count} 次</p><a href={`/alerts/${item.id}`}>查看证据</a></div>)}</>}
  </section>
}

export function Rules() {
  const [rule, setRule] = useState<unknown>(null)
  const [error, setError] = useState('')
  useEffect(() => { const controller = new AbortController(); businessRequest('/rules/R-001', { signal: controller.signal }).then(setRule).catch((cause: unknown) => { if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : '加载失败') }); return () => controller.abort() }, [])
  return <section className="panel"><h2>固定发布规则 R-001</h2>{error && <p className="error-message" role="alert">{error}</p>}
    {rule !== null && <pre>{JSON.stringify(rule, null, 2)}</pre>}<p>规则草稿、发布和版本治理仍在后续增量开发。</p></section>
}
