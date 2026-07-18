import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'

vi.mock('quasar', () => ({
  Notify: { create: vi.fn() },
  Dialog: { create: vi.fn() },
  copyToClipboard: vi.fn(async () => {}),
}))

vi.mock('qrcode', () => ({ default: { toDataURL: vi.fn(async () => 'data:image/png;base64,QR') } }))

const get = vi.fn()
const post = vi.fn()
vi.mock('@/api/axios', () => ({ default: { get: (...a) => get(...a), post: (...a) => post(...a) } }))

vi.mock('@/composables/useTheme', () => ({
  themes: [], applyTheme: vi.fn(), getSavedTheme: () => 'light',
}))

import UserProfilePage from '@/views/UserProfilePage.vue'

// q-input carries v-model; q-btn forwards click; q-dialog renders its slot
// when open; everything else is a passthrough container.
const QInput = {
  name: 'QInput',
  props: ['modelValue', 'label', 'type'],
  emits: ['update:modelValue'],
  template:
    '<input :aria-label="label" :value="modelValue" ' +
    '@input="$emit(\'update:modelValue\', $event.target.value)" />',
}
const QBtn = {
  name: 'QBtn',
  props: ['label'],
  template: '<button @click="$emit(\'click\')">{{ label }}<slot /></button>',
}
const QDialog = {
  name: 'QDialog',
  props: ['modelValue'],
  template: '<div v-if="modelValue"><slot /></div>',
}
const pass = (name) => ({ name, template: '<div><slot /></div>' })

function mountProfile() {
  return mount(UserProfilePage, {
    global: {
      stubs: {
        QInput, QBtn, QDialog,
        QPage: pass('QPage'), QCard: pass('QCard'), QCardSection: pass('QCardSection'),
        QBanner: pass('QBanner'), QBadge: pass('QBadge'), QSpace: pass('QSpace'),
        QIcon: pass('QIcon'), QSpinnerDots: pass('QSpinnerDots'),
      },
    },
  })
}

function btnByLabel(wrapper, label) {
  return wrapper.findAll('button').find((b) => b.text().includes(label))
}

describe('2FA enrollment (My Profile)', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    get.mockReset()
    post.mockReset()
    // onMounted: /auth/me then /2fa/status (enabled globally, user not enrolled)
    get.mockImplementation((url) => {
      if (url === '/auth/me') return Promise.resolve({ data: { id: 7, username: 'alice', email: 'a@x' } })
      if (url === '/2fa/status') return Promise.resolve({ data: { mode: 'enabled', enrolled: false, setup_required: false } })
      return Promise.resolve({ data: {} })
    })
  })
  afterEach(() => vi.clearAllMocks())

  it('walks password -> QR -> confirm and enables 2FA with backup codes', async () => {
    post.mockImplementation((url) => {
      if (url === '/2fa/setup') return Promise.resolve({ data: { secret: 'S3CR3T', provisioning_uri: 'otpauth://x' } })
      if (url === '/2fa/enable') return Promise.resolve({ data: { backup_codes: ['111', '222'] } })
      return Promise.resolve({ data: {} })
    })
    const wrapper = mountProfile()
    await flushPromises()

    // Open the setup dialog
    await btnByLabel(wrapper, 'Set up 2FA').trigger('click')
    await flushPromises()

    // Step 1: enter password, Continue → /2fa/setup
    await wrapper.findAll('input').find((i) => i.attributes('aria-label') === 'Password').setValue('pw')
    await btnByLabel(wrapper, 'Continue').trigger('click')
    await flushPromises()
    expect(post).toHaveBeenCalledWith('/2fa/setup', { password: 'pw' })

    // Step 2: QR rendered from provisioning_uri, enter code, verify → /2fa/enable
    const QRCode = (await import('qrcode')).default
    expect(QRCode.toDataURL).toHaveBeenCalledWith('otpauth://x', expect.anything())
    await wrapper.findAll('input').find((i) => i.attributes('aria-label') === '6-digit code').setValue('123456')
    await btnByLabel(wrapper, 'Verify and enable').trigger('click')
    await flushPromises()
    expect(post).toHaveBeenCalledWith('/2fa/enable', { code: '123456' })

    // Step 3: backup codes surfaced to the user
    expect(wrapper.text()).toContain('111')
    expect(wrapper.text()).toContain('222')
  })

  it('does not enable when the confirmation code is rejected', async () => {
    post.mockImplementation((url) => {
      if (url === '/2fa/setup') return Promise.resolve({ data: { secret: 'S', provisioning_uri: 'otpauth://y' } })
      if (url === '/2fa/enable') return Promise.reject({ response: { data: { detail: 'Invalid code' } } })
      return Promise.resolve({ data: {} })
    })
    const wrapper = mountProfile()
    await flushPromises()
    await btnByLabel(wrapper, 'Set up 2FA').trigger('click')
    await flushPromises()
    await wrapper.findAll('input').find((i) => i.attributes('aria-label') === 'Password').setValue('pw')
    await btnByLabel(wrapper, 'Continue').trigger('click')
    await flushPromises()
    await wrapper.findAll('input').find((i) => i.attributes('aria-label') === '6-digit code').setValue('000000')
    await btnByLabel(wrapper, 'Verify and enable').trigger('click')
    await flushPromises()

    // /2fa/enable was attempted but failed
    expect(post).toHaveBeenCalledWith('/2fa/enable', { code: '000000' })
    // Status is reloaded only on success, so it stays at the single onMounted call
    const statusCalls = get.mock.calls.filter(([url]) => url === '/2fa/status').length
    expect(statusCalls).toBe(1)
  })
})
