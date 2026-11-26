import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource/geist/latin-400.css'
import '@fontsource/geist/latin-600.css'
import { AuthGate } from './features/auth/AuthGate'
import './shared/styles/base.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode><AuthGate /></StrictMode>,
)
