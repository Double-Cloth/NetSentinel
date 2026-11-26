import { useEffect, useState, type FormEvent } from 'react'
import { App } from '../../app/App'
import { ApiError } from '../../shared/api/client'
import { requestSession, type Session } from '../../shared/api/session'

type AuthState =
  | { phase: 'loading' | 'anonymous' }
  | { phase: 'error'; message: string }
  | { phase: 'authenticated'; session: Session }

export function AuthGate() {
  const [state, setState] = useState<AuthState>({ phase: 'loading' })
  const [attempt, setAttempt] = useState(0)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    const controller = new AbortController()
    requestSession('me', { signal: controller.signal }).then(
      session => setState({ phase: 'authenticated', session }),
      (failure: ApiError) => {
        if (controller.signal.aborted) return
        setState(failure.status === 401 ? { phase: 'anonymous' } : { phase: 'error', message: failure.message })
      },
    )
    return () => controller.abort()
  }, [attempt])

  useEffect(() => {
    if (state.phase !== 'authenticated') document.title = 'NetSentinel · 登录'
  }, [state.phase])

  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (pending) return
    const form = event.currentTarget
    const values = new FormData(form)
    const password = form.elements.namedItem('password')
    setPending(true)
    setError('')
    try {
      const session = await requestSession('login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: values.get('username'), password: values.get('password') }),
      })
      setState({ phase: 'authenticated', session })
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : '登录失败，请重试。')
      if (password instanceof HTMLInputElement) {
        password.value = ''
        password.focus()
      }
    } finally {
      setPending(false)
    }
  }

  async function logout(session: Session) {
    if (pending) return
    setPending(true)
    setError('')
    try {
      await requestSession('logout', { method: 'POST', headers: { 'X-CSRF-Token': session.csrf_token } })
      setState({ phase: 'anonymous' })
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        setState({ phase: 'anonymous' })
      } else {
        setError(failure instanceof ApiError ? failure.message : '退出登录失败，请重试。')
      }
    } finally {
      setPending(false)
    }
  }

  if (state.phase === 'authenticated') {
    return <App username={state.session.user.username} logoutPending={pending} logoutError={error} onLogout={() => void logout(state.session)} />
  }

  return (
    <main className="sign-in">
      <section className="panel" aria-labelledby="sign-in-heading">
        <p className="sign-in-brand">NetSentinel</p>
        <h1 id="sign-in-heading">登录</h1>
        {state.phase === 'loading' && <p role="status">正在检查会话…</p>}
        {state.phase === 'error' && <>
          <p className="error-message" role="alert">{state.message}</p>
          <button type="button" onClick={() => { setState({ phase: 'loading' }); setAttempt(value => value + 1) }}>重试</button>
        </>}
        {state.phase === 'anonymous' && (
          <form className="sign-in-form" method="post" onSubmit={login}>
            <label htmlFor="username">用户名</label>
            <input id="username" name="username" autoComplete="username" autoCapitalize="none" autoCorrect="off" spellCheck={false} required />
            <label htmlFor="password">密码</label>
            <input id="password" name="password" type="password" autoComplete="current-password" enterKeyHint="done" required />
            <button type="submit" disabled={pending}>{pending ? '正在登录…' : '登录'}</button>
            <p className="error-message" role="alert">{error}</p>
          </form>
        )}
      </section>
    </main>
  )
}
