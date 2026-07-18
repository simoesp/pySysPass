import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@/api/axios', () => ({
  default: { get: vi.fn() },
}))

import api from '@/api/axios'
import { encryptPassword } from '@/composables/useClientEncryption'

describe('client-side password encryption', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns empty values unchanged', async () => {
    expect(await encryptPassword('')).toBe('')
    expect(await encryptPassword(null)).toBeNull()
  })

  it('falls back to plaintext when the public key cannot be fetched', async () => {
    api.get.mockRejectedValue(new Error('server down'))
    expect(await encryptPassword('secret')).toBe('secret')
  })
})
