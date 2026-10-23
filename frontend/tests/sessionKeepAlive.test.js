import { describe, it, expect } from 'vitest'
import { decodeTokenClaims, shouldRefresh } from '@/composables/useSessionKeepAlive'

function token(claims) {
  const encode = value => btoa(JSON.stringify(value)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  return `${encode({ alg: 'HS256' })}.${encode(claims)}.signature`
}

describe('session keep-alive', () => {
  it('decodes base64url JWT claims', () => {
    expect(decodeTokenClaims(token({ iat: 100, exp: 400, sub: '~~~?' }))).toEqual({ iat: 100, exp: 400, sub: '~~~?' })
    expect(decodeTokenClaims('not-a-token')).toBeNull()
  })

  it('refreshes only after user input and half of the window', () => {
    const claims = { iat: 1000, exp: 1300 }
    expect(shouldRefresh(claims, 1100, 1100)).toBe(false) // too early
    expect(shouldRefresh(claims, 1200, 1200)).toBe(true)
    expect(shouldRefresh(claims, 0, 1200)).toBe(false)    // idle since issue: let it expire
    expect(shouldRefresh(claims, 999, 1200)).toBe(false)  // input predates this token
    expect(shouldRefresh(claims, 1290, 1301)).toBe(false) // already expired
    expect(shouldRefresh(null, 1200, 1200)).toBe(false)
  })
})
