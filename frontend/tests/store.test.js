import { beforeEach, describe, expect, it } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { useMainStore } from '@/stores'

describe('main store', () => {
  beforeEach(() => {
    localStorage.clear()
    setActivePinia(createPinia())
  })

  it('persists the token to localStorage', () => {
    const store = useMainStore()
    store.setToken('tok-123')
    expect(store.token).toBe('tok-123')
    expect(localStorage.getItem('auth_token')).toBe('tok-123')
    expect(store.isAuthenticated).toBe(true)
  })

  it('clearToken wipes token and user', () => {
    const store = useMainStore()
    store.setToken('tok-123')
    store.setUser({ id: 1, username: 'alice' })
    store.clearToken()
    expect(store.token).toBeNull()
    expect(store.user).toBeNull()
    expect(localStorage.getItem('auth_token')).toBeNull()
    expect(store.isAuthenticated).toBe(false)
  })

  it('hasPermission grants everything to admins', () => {
    const store = useMainStore()
    store.setUser({ id: 1, is_admin: true, permissions: null })
    expect(store.hasPermission('mgm_users')).toBe(true)
    expect(store.hasPermission('anything')).toBe(true)
  })

  it('hasPermission follows profile flags for non-admins', () => {
    const store = useMainStore()
    store.setUser({ id: 2, is_admin: false, permissions: { mgm_users: true } })
    expect(store.hasPermission('mgm_users')).toBe(true)
    expect(store.hasPermission('config_general')).toBe(false)
  })

  it('hasPermission denies when no user is set', () => {
    const store = useMainStore()
    expect(store.hasPermission('mgm_users')).toBe(false)
  })
})
