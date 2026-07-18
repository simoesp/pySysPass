import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import api from '@/api/axios'
import { useMainStore } from '@/stores'

function requestHandler() {
  return api.interceptors.request.handlers[0].fulfilled
}

function responseRejectHandler() {
  return api.interceptors.response.handlers[0].rejected
}

describe('axios interceptors', () => {
  beforeEach(() => {
    localStorage.clear()
    setActivePinia(createPinia())
    Object.defineProperty(window, 'location', {
      value: { href: '' },
      writable: true,
      configurable: true,
    })
  })

  it('attaches the bearer token when logged in', () => {
    useMainStore().setToken('tok-abc')
    const config = requestHandler()({ headers: {} })
    expect(config.headers.Authorization).toBe('Bearer tok-abc')
  })

  it('sends no auth header when logged out', () => {
    const config = requestHandler()({ headers: {} })
    expect(config.headers.Authorization).toBeUndefined()
  })

  it('401 on a normal route clears the session and redirects to login', async () => {
    const store = useMainStore()
    store.setToken('tok-abc')
    const error = { config: { url: '/accounts' }, response: { status: 401 } }
    await expect(responseRejectHandler()(error)).rejects.toBe(error)
    expect(store.token).toBeNull()
    expect(window.location.href).toBe('/login')
  })

  it('401 on /auth/login does not redirect (login form shows the error)', async () => {
    const store = useMainStore()
    store.setToken('tok-abc')
    const error = { config: { url: '/auth/login' }, response: { status: 401 } }
    await expect(responseRejectHandler()(error)).rejects.toBe(error)
    expect(store.token).toBe('tok-abc')
    expect(window.location.href).toBe('')
  })

  it('non-401 errors pass through untouched', async () => {
    const store = useMainStore()
    store.setToken('tok-abc')
    const error = { config: { url: '/accounts' }, response: { status: 500 } }
    await expect(responseRejectHandler()(error)).rejects.toBe(error)
    expect(store.token).toBe('tok-abc')
  })
})
