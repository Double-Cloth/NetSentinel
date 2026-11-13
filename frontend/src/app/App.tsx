import { useEffect, useState, type MouseEvent } from 'react'
import { HealthPanel } from '../features/overview/HealthPanel'
import { modules, progress } from './modules'

export function App() {
  const [path, setPath] = useState(window.location.pathname)
  const [menuOpen, setMenuOpen] = useState(false)
  const page = modules.find(item => item.path === path)

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
        <span className="stage-label">工程基础</span>
        <button className="menu-toggle" type="button" aria-expanded={menuOpen} aria-controls="navigation" onClick={() => setMenuOpen(value => !value)}>菜单</button>
      </header>
      <aside className={`sidebar ${menuOpen ? 'is-open' : ''}`}>
        <nav id="navigation" aria-label="主要导航">
          {modules.map(item => <a key={item.path} href={item.path} aria-current={path === item.path ? 'page' : undefined} onClick={event => navigate(event, item.path)}>{item.label}</a>)}
        </nav>
        <p className="sidebar-note">离线日志分析<br />Go · React · SQLite</p>
      </aside>
      <main id="main">
        <div className="content">
          <h1 id="page-heading" tabIndex={-1}>{page?.label ?? '页面不存在'}</h1>
          {path === '/' ? <>
            <p className="page-description">授权日志的离线分析与证据追溯</p>
            <HealthPanel />
            <section className="panel" aria-labelledby="progress-heading">
              <h2 id="progress-heading">开发进度</h2>
              <div className="table-scroll" role="region" aria-label="模块开发进度" tabIndex={0}>
                <table><thead><tr><th scope="col">模块</th><th scope="col">当前能力</th><th scope="col">后续计划</th></tr></thead>
                  <tbody>{progress.map(([name, current, next]) => <tr key={name}><th scope="row">{name}</th><td>{current}</td><td>{next}</td></tr>)}</tbody>
                </table>
              </div>
            </section>
            <p className="stage-note">基础框架阶段，业务流程按项目增量计划接入。</p>
          </> : page ? <section className="module-state" aria-labelledby="module-heading">
            <h2 id="module-heading">模块基础已建立</h2>
            <p>{page.current}</p><p className="muted">{page.next}</p>
            <a href="/" onClick={event => navigate(event, '/')}>返回工作台</a>
          </section> : <p>请通过侧导航访问项目页面。</p>}
        </div>
      </main>
    </div>
  )
}
