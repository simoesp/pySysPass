import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'

// LoginPage pulls Notify from quasar and registers q-* globally; we mock
// Notify and stub the four q-components it uses so no real Quasar (whose
// SSR build breaks under jsdom) is loaded.
vi.mock('quasar', () => ({ Notify: { create: vi.fn() } }))

const push = vi.fn()
vi.mock('vue-router', () => ({ useRouter: () => ({ push }) }))

const post = vi.fn()
vi.mock('@/api/axios', () => ({ default: { post: (...a) => post(...a) } }))

vi.mock('@/composables/useClientEncryption', () => ({
  encryptPassword: async (v) => v,
  preloadEncryptionKey: async () => {},
}))

import LoginPage from '@/views/LoginPage.vue'

const QInput = {
  name: 'QInput',
  props: ['modelValue', 'placeholder', 'type', 'disable'],
  emits: ['update:modelValue'],
  template:
    '<input :placeholder="placeholder" :value="modelValue" ' +
    '@input="$emit(\'update:modelValue\', $event.target.value)" />',
}
const QForm = {
  name: 'QForm',
  emits: ['submit'],
  // Pass the native event through: LoginPage binds @submit.prevent, which
  // calls preventDefault() on the emitted payload.
  template: '<form @submit="$emit(\'submit\', $event)"><slot /></form>',
}
const passthrough = (name) => ({ name, template: '<div><slot /></div>' })

function mountLogin() {
  return mount(LoginPage, {
    global: {
      stubs: { QInput, QForm, QBtn: passthrough('QBtn'), QIcon: passthrough('QIcon') },
    },
  })
}

function challenge(code) {
  return { response: { status: 428, data: { detail: { code, message: code } } } }
}

async function submitCredentials(wrapper) {
  const inputs = wrapper.findAll('input')
  await inputs[0].setValue('alice')
  await inputs[1].setValue('secret')
  await wrapper.find('form').trigger('submit')
  await flushPromises()
}

function hasPlaceholder(wrapper, text) {
  return wrapper.findAll('input').some(
    (i) => (i.attributes('placeholder') || '').includes(text),
  )
}

describe('LoginPage challenge flow', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    push.mockClear()
    post.mockReset()
  })
  afterEach(() => vi.clearAllMocks())

  it('reveals the OTP field on a TWO_FACTOR_REQUIRED challenge', async () => {
    post.mockRejectedValueOnce(challenge('TWO_FACTOR_REQUIRED'))
    const wrapper = mountLogin()
    expect(hasPlaceholder(wrapper, '6-digit code')).toBe(false)

    await submitCredentials(wrapper)

    expect(hasPlaceholder(wrapper, '6-digit code')).toBe(true)
    expect(push).not.toHaveBeenCalled()
  })

  it('reveals the master-password field on a MASTER_PASSWORD_REQUIRED challenge', async () => {
    post.mockRejectedValueOnce(challenge('MASTER_PASSWORD_REQUIRED'))
    const wrapper = mountLogin()

    await submitCredentials(wrapper)

    expect(hasPlaceholder(wrapper, 'master password')).toBe(true)
  })

  it('reveals the previous-password field on an OLD_PASSWORD_REQUIRED challenge', async () => {
    post.mockRejectedValueOnce(challenge('OLD_PASSWORD_REQUIRED'))
    const wrapper = mountLogin()

    await submitCredentials(wrapper)

    expect(hasPlaceholder(wrapper, 'previous password')).toBe(true)
  })

  it('stores the token and routes to /accounts on success', async () => {
    post.mockResolvedValueOnce({ data: { access_token: 'tok-xyz' } })
    const wrapper = mountLogin()

    await submitCredentials(wrapper)

    const { useMainStore } = await import('@/stores')
    expect(useMainStore().token).toBe('tok-xyz')
    expect(push).toHaveBeenCalledWith('/accounts')
  })

  it('resubmits with the otp field once the OTP challenge is shown', async () => {
    post
      .mockRejectedValueOnce(challenge('TWO_FACTOR_REQUIRED'))
      .mockResolvedValueOnce({ data: { access_token: 'tok-2fa' } })
    const wrapper = mountLogin()

    await submitCredentials(wrapper)
    const otp = wrapper.findAll('input').find(
      (i) => (i.attributes('placeholder') || '').includes('6-digit code'),
    )
    await otp.setValue('123456')
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    const body = post.mock.calls[1][1]
    expect(body.toString()).toContain('otp=123456')
    expect(push).toHaveBeenCalledWith('/accounts')
  })
})
