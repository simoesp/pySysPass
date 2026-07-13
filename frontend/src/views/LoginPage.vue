<template>
  <div class="sp-login-wrap">
    <!-- Left panel – branding -->
    <div class="sp-login-brand gt-sm">
      <div class="sp-brand-inner">
        <div class="sp-brand-logo">
          <q-icon name="shield" size="56px" color="white" />
        </div>
        <div class="sp-brand-name">sys<strong>Pass</strong></div>
        <div class="sp-brand-tagline">Secure password management<br>for teams and individuals</div>
        <div class="sp-brand-bullets">
          <div v-for="b in bullets" :key="b.icon" class="sp-bullet">
            <q-icon :name="b.icon" size="18px" />
            <span>{{ b.text }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Right panel – form -->
    <div class="sp-login-form-panel">
      <div class="sp-login-form-inner">
        <!-- Mobile logo -->
        <div class="sp-mobile-logo lt-md text-center q-mb-lg">
          <q-icon name="shield" size="40px" color="primary" />
          <div class="text-h5 text-weight-bold text-primary">sys<strong>Pass</strong></div>
        </div>

        <div class="text-h5 text-weight-bold text-grey-9 q-mb-xs">Welcome back</div>
        <div class="text-body2 text-grey-6 q-mb-xl">
          {{ loginPrompt }}
        </div>

        <q-form @submit.prevent="onSubmit" class="q-gutter-y-md">
          <div>
            <div class="sp-field-label">Username</div>
            <q-input
              v-model="username"
              outlined
              dense
              placeholder="Enter your username"
              autocomplete="username"
              :disable="loading"
              bg-color="white"
            >
              <template v-slot:prepend>
                <q-icon name="person_outline" color="grey-5" />
              </template>
            </q-input>
          </div>

          <div>
            <div class="row items-center justify-between q-mb-xs">
              <span class="sp-field-label">Password</span>
              <q-btn flat dense no-caps size="sm" color="primary" label="Forgot password?" @click="$router.push('/password-reset')" />
            </div>
            <q-input
              v-model="password"
              :type="showPwd ? 'text' : 'password'"
              outlined
              dense
              placeholder="Enter your password"
              autocomplete="current-password"
              :disable="loading"
              bg-color="white"
            >
              <template v-slot:prepend>
                <q-icon name="lock_outline" color="grey-5" />
              </template>
              <template v-slot:append>
                <q-icon
                  :name="showPwd ? 'visibility_off' : 'visibility'"
                  color="grey-5"
                  class="cursor-pointer"
                  @click="showPwd = !showPwd"
                />
              </template>
            </q-input>
          </div>

          <div v-if="requiresMasterPassword">
            <div class="sp-field-label">Master Password</div>
            <q-input
              v-model="masterPassword"
              :type="showMasterPwd ? 'text' : 'password'"
              outlined
              dense
              placeholder="Enter your master password"
              autocomplete="off"
              :disable="loading"
              bg-color="white"
            >
              <template v-slot:prepend>
                <q-icon name="key" color="grey-5" />
              </template>
              <template v-slot:append>
                <q-icon
                  :name="showMasterPwd ? 'visibility_off' : 'visibility'"
                  color="grey-5"
                  class="cursor-pointer"
                  @click="showMasterPwd = !showMasterPwd"
                />
              </template>
            </q-input>
            <div class="text-caption text-warning q-mt-xs">
              {{ masterPasswordPrompt }}
            </div>
          </div>

          <div v-if="requiresOldPassword">
            <div class="sp-field-label">Previous Password</div>
            <q-input
              v-model="oldPassword"
              :type="showOldPwd ? 'text' : 'password'"
              outlined
              dense
              placeholder="Enter your previous password"
              autocomplete="off"
              :disable="loading"
              bg-color="white"
            >
              <template v-slot:prepend>
                <q-icon name="history" color="grey-5" />
              </template>
              <template v-slot:append>
                <q-icon
                  :name="showOldPwd ? 'visibility_off' : 'visibility'"
                  color="grey-5"
                  class="cursor-pointer"
                  @click="showOldPwd = !showOldPwd"
                />
              </template>
            </q-input>
            <div class="text-caption text-warning q-mt-xs">
              {{ oldPasswordPrompt }}
            </div>
          </div>

          <q-btn
            type="submit"
            unelevated
            color="primary"
            :label="requiresMasterPassword || requiresOldPassword ? 'Unlock vault' : 'Sign in'"
            class="full-width sp-signin-btn"
            :loading="loading"
            no-caps
          />
        </q-form>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { Notify } from 'quasar'
import { useMainStore } from '@/stores'
import api from '@/api/axios'
import { encryptPassword, preloadEncryptionKey } from '@/composables/useClientEncryption'

const router = useRouter()
const store = useMainStore()

const username = ref('')
const password = ref('')
const masterPassword = ref('')
const oldPassword = ref('')
const showPwd = ref(false)
const showMasterPwd = ref(false)
const showOldPwd = ref(false)
const loading = ref(false)
const requiresMasterPassword = ref(false)
const requiresOldPassword = ref(false)
const masterPasswordPrompt = ref('')
const oldPasswordPrompt = ref('')

onMounted(() => preloadEncryptionKey())

const bullets = [
  { icon: 'lock', text: 'AES-256 encryption at rest' },
  { icon: 'group', text: 'Shared vaults for teams' },
  { icon: 'history', text: 'Full audit history' },
]

const loginPrompt = computed(() => {
  if (requiresOldPassword.value) return 'Enter your previous password to migrate your vault encryption key'
  if (requiresMasterPassword.value) return 'Enter your master password to unlock the vault'
  return 'Sign in to your password vault'
})

function getErrorDetail(error) {
  return error?.response?.data?.detail ?? error?.response?.data ?? null
}

function getErrorCode(error) {
  const detail = getErrorDetail(error)
  if (typeof detail === 'object' && detail !== null) return detail.code || null
  return error?.response?.data?.code || null
}

function getErrorMessage(error, fallback = 'Invalid credentials') {
  const detail = getErrorDetail(error)
  if (typeof detail === 'string' && detail.trim()) return detail
  if (typeof detail === 'object' && detail !== null) {
    if (typeof detail.message === 'string' && detail.message.trim()) return detail.message
    if (typeof detail.detail === 'string' && detail.detail.trim()) return detail.detail
    try {
      return JSON.stringify(detail)
    } catch {
      return fallback
    }
  }
  if (typeof error?.message === 'string' && error.message.trim()) return error.message
  return fallback
}

async function onSubmit() {
  if (!username.value || !password.value) {
    Notify.create({ message: 'Please enter your username and password', color: 'warning' })
    return
  }
  if (requiresMasterPassword.value && !masterPassword.value) {
    Notify.create({ message: 'Please enter your master password', color: 'warning' })
    return
  }
  if (requiresOldPassword.value && !oldPassword.value) {
    Notify.create({ message: 'Please enter your previous password', color: 'warning' })
    return
  }
  loading.value = true
  try {
    const encPwd = await encryptPassword(password.value)
    const form = new URLSearchParams()
    form.append('username', username.value)
    form.append('password', encPwd)
    if (requiresMasterPassword.value && masterPassword.value) {
      form.append('mpass', await encryptPassword(masterPassword.value))
    }
    if (requiresOldPassword.value && oldPassword.value) {
      form.append('oldpass', await encryptPassword(oldPassword.value))
    }
    const r = await api.post('/auth/login', form, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    })
    store.setToken(r.data.access_token)
    requiresMasterPassword.value = false
    requiresOldPassword.value = false
    masterPassword.value = ''
    oldPassword.value = ''
    masterPasswordPrompt.value = ''
    oldPasswordPrompt.value = ''
    router.push('/accounts')
  } catch (e) {
    if (e.response?.status === 428) {
      const code = getErrorCode(e)
      if (code === 'OLD_PASSWORD_REQUIRED') {
        requiresOldPassword.value = true
        requiresMasterPassword.value = false
        masterPassword.value = ''
        oldPasswordPrompt.value = getErrorMessage(e, 'Your previous password is needed to unlock and migrate your vault')
      } else {
        requiresMasterPassword.value = true
        requiresOldPassword.value = false
        oldPassword.value = ''
        masterPasswordPrompt.value = getErrorMessage(e, 'Master password required to unlock your vault')
      }
      Notify.create({
        message: code === 'OLD_PASSWORD_REQUIRED' ? oldPasswordPrompt.value : masterPasswordPrompt.value,
        color: 'warning',
        icon: code === 'OLD_PASSWORD_REQUIRED' ? 'history' : 'key',
      })
      return
    }
    Notify.create({
      message: getErrorMessage(e),
      color: 'negative',
      icon: 'error',
    })
  } finally {
    loading.value = false
  }
}
</script>

<style lang="scss" scoped>
.sp-login-wrap {
  display: flex;
  min-height: 100vh;
  background: var(--sp-content-bg, #f4f6fb);
}

// ── Left branding panel ───────────────────────────────────────────────────
.sp-login-brand {
  flex: 0 0 420px;
  background: linear-gradient(145deg, #1a237e 0%, #283593 60%, #3949ab 100%);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 48px;
}

.sp-brand-inner {
  color: #fff;
  max-width: 280px;
}

.sp-brand-logo {
  width: 80px;
  height: 80px;
  background: rgba(255,255,255,.12);
  border-radius: 20px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 24px;
}

.sp-brand-name {
  font-size: 32px;
  font-weight: 300;
  letter-spacing: -0.5px;
  margin-bottom: 12px;
  strong { font-weight: 800; }
}

.sp-brand-tagline {
  font-size: 15px;
  line-height: 1.5;
  color: rgba(255,255,255,.7);
  margin-bottom: 40px;
}

.sp-brand-bullets {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.sp-bullet {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 13px;
  color: rgba(255,255,255,.75);
}

// ── Right form panel ──────────────────────────────────────────────────────
.sp-login-form-panel {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 32px 24px;
  background: var(--sp-card-bg, #ffffff);
}

.sp-login-form-inner {
  width: 100%;
  max-width: 380px;
}

.sp-field-label {
  font-size: 13px;
  font-weight: 600;
  color: var(--sp-text-primary, #374151);
  margin-bottom: 6px;
}

.sp-signin-btn {
  height: 44px;
  font-size: 15px;
  font-weight: 600;
  border-radius: 8px;
  margin-top: 8px;
}

.sp-mobile-logo {
  .text-h5 { letter-spacing: -.5px; }
}
</style>
