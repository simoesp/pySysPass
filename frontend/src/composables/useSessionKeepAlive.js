import api from '@/api/axios'
import { useMainStore } from '@/stores'

// Session tokens expire after the server's inactivity timeout (sysPass
// session_timeout). Only real user input renews them: background polling must
// not keep an idle session alive, matching PHP's inactivity semantics.
const INPUT_EVENTS = ['pointerdown', 'keydown', 'wheel', 'touchstart']
const CHECK_INTERVAL_MS = 15000

export function decodeTokenClaims(token) {
  try {
    const part = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')
    return JSON.parse(atob(part.padEnd(part.length + (4 - part.length % 4) % 4, '=')))
  } catch {
    return null
  }
}

// Renew once at least half of the window has elapsed, and only if the user
// interacted since the current token was issued.
export function shouldRefresh(claims, lastInputSeconds, nowSeconds) {
  if (!claims?.exp || !claims?.iat) return false
  if (lastInputSeconds < claims.iat) return false
  if (nowSeconds >= claims.exp) return false
  return nowSeconds - claims.iat >= (claims.exp - claims.iat) / 2
}

export function useSessionKeepAlive() {
  const store = useMainStore()
  let lastInput = 0
  let timer = null
  let refreshing = false

  const markInput = () => { lastInput = Date.now() / 1000 }

  async function check() {
    const claims = store.token ? decodeTokenClaims(store.token) : null
    if (refreshing || !shouldRefresh(claims, lastInput, Date.now() / 1000)) return
    refreshing = true
    try {
      const r = await api.post('/auth/refresh')
      store.setToken(r.data.access_token)
    } catch { /* an expired session is handled by the 401 interceptor */ } finally {
      refreshing = false
    }
  }

  function start() {
    INPUT_EVENTS.forEach(name => window.addEventListener(name, markInput, { passive: true }))
    timer = setInterval(check, CHECK_INTERVAL_MS)
  }

  function stop() {
    INPUT_EVENTS.forEach(name => window.removeEventListener(name, markInput))
    clearInterval(timer)
    timer = null
  }

  return { start, stop, check, markInput }
}
