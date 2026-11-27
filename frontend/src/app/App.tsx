import { useEffect, useState, type MouseEvent } from 'react'
import { HealthPanel } from '../features/overview/HealthPanel'
import { Alerts, Datasets, Overview, Rules, Sources, Tasks } from '../features/business/Pages'
import type { Session } from '../shared/api/session'
import { modules } from './modules'

interface AppProps {
  session: Session
  logoutPending: boolean
  logoutError: string
  onLogout: () => void
}

export function App({ session, logoutPending, logoutError, onLogout }: AppProps) {
  const [path, setPath] = useState(window.location.pathname)
  const [menuOpen, setMenuOpen] = useState(false)
  const page = modules.find(item => item.path === path || (item.path !== '/' && path.startsWith(`${item.path}/`)))

  useEffect(() => {
    const update = () => { setPath(window.location.pathname); setMenuOpen(false) }
    window.addEventListener('popstate', update)
    return () => window.removeEventListener('popstate', update)
  }, [])

  useEffect(() => { document.title = `NetSentinel · ${page?.label ?? '页面不存在'}` }, [page])

  function navigate(event: MouseEvent<HTMLAnchorElement>, target: string) {
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
    event.preventDefault()
    window.history.pushState(null, '', target)
    setPath(target)
    setMenuOpen(false)
    window.scrollTo(0, 0)
    window.requestAnimationFrame(() => document.getElementById('page-heading')?.focus())
  }

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main">跳到主要内容</a>
      <header className="topbar">
        <a className="brand" href="/" onClick={event => navigate(event, '/')}>NetSentinel</a>
        <button className="menu-toggle" type="button" aria-expanded={menuOpen} aria-controls="navigation" onClick={() => setMenuOpen(value => !value)}>菜单</button>
        <div className="account-controls">
          <span className="stage-label">{session.user.username} · {session.user.role}</span>
          <button type="button" disabled={logoutPending} onClick={onLogout}>{logoutPending ? '正在退出…' : '退出登录'}</button>
        </div>
      </header>
      <aside className={`sidebar ${menuOpen ? 'is-open' : ''}`}>
        <nav id="navigation" aria-label="主要导航">
          {modules.map(item => <a key={item.path} href={item.path} aria-current={path === item.path ? 'page' : undefined} onClick={event => navigate(event, item.path)}>{item.label}</a>)}
        </nav>
      </aside>
      <main id="main">
        <div className="content">
          {logoutError && <p className="error-message" role="alert">{logoutError}</p>}
          <h1 id="page-heading" tabIndex={-1}>{page?.label ?? '页面不存在'}</h1>
          {path === '/' ? <>
            <p className="page-description">授权日志定时采集、批次分析与证据追溯</p>
            <Overview /><HealthPanel />
          </> : path === '/settings' ? <Sources session={session} />
            : path === '/datasets' || path.startsWith('/datasets/') ? <Datasets id={path.split('/')[2]} />
              : path === '/tasks' ? <Tasks session={session} />
                : path === '/alerts' || path.startsWith('/alerts/') ? <Alerts id={path.split('/')[2]} />
                  : path === '/rules' ? <Rules />
                    : page ? <section className="module-state"><h2>开发中</h2><p>{page.next}</p></section>
                      : <p>页面不存在，请通过侧导航访问。</p>}
        </div>
      </main>
    </div>
  )
}
