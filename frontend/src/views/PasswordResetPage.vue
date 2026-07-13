<template>
  <div class="sp-login-wrap">
    <div class="sp-login-brand gt-sm">
      <div class="sp-brand-inner">
        <div class="sp-brand-logo"><q-icon name="shield" size="56px" color="white" /></div>
        <div class="sp-brand-name">sys<strong>Pass</strong></div>
        <div class="sp-brand-tagline">Secure password management<br>for teams and individuals</div>
      </div>
    </div>

    <div class="sp-login-form-panel">
      <div class="sp-login-form-inner">
        <div class="sp-mobile-logo lt-md text-center q-mb-lg">
          <q-icon name="shield" size="40px" color="primary" />
          <div class="text-h5 text-weight-bold text-primary">sys<strong>Pass</strong></div>
        </div>

        <!-- ── Step 1: request reset ──────────────────────────────── -->
        <template v-if="!token">
          <div class="text-h5 text-weight-bold text-grey-9 q-mb-xs">Reset your password</div>
          <div class="text-body2 text-grey-6 q-mb-xl">Enter your email and we'll send you a reset link.</div>

          <div v-if="requested" class="text-center q-py-lg">
            <q-icon name="mark_email_read" size="64px" color="positive" />
            <div class="text-h6 q-mt-md">Check your inbox</div>
            <div class="text-body2 text-grey-6 q-mt-sm">If that email is registered, a reset link is on its way.</div>
            <q-btn flat color="primary" label="Back to login" class="q-mt-lg" no-caps @click="$router.push('/login')" />
          </div>

          <q-form v-else @submit.prevent="doRequest" class="q-gutter-y-md">
            <div>
              <div class="sp-field-label">Email address</div>
              <q-input v-model="email" type="email" outlined dense placeholder="you@example.com"
                autocomplete="email" :disable="loading" bg-color="white">
                <template v-slot:prepend><q-icon name="email" color="grey-5" /></template>
              </q-input>
            </div>
            <q-btn type="submit" unelevated color="primary" label="Send reset link"
              class="full-width sp-signin-btn" :loading="loading" no-caps />
            <div class="text-center">
              <q-btn flat dense no-caps color="primary" label="Back to login" @click="$router.push('/login')" />
            </div>
          </q-form>
        </template>

        <!-- ── Step 2: set new password ──────────────────────────── -->
        <template v-else>
          <div class="text-h5 text-weight-bold text-grey-9 q-mb-xs">Set new password</div>
          <div class="text-body2 text-grey-6 q-mb-xl" v-if="verifiedUser">
            Resetting password for <strong>{{ verifiedUser }}</strong>
          </div>

          <div v-if="tokenInvalid" class="text-center q-py-lg">
            <q-icon name="link_off" size="64px" color="negative" />
            <div class="text-h6 q-mt-md">Link expired or invalid</div>
            <div class="text-body2 text-grey-6 q-mt-sm">Request a new reset link.</div>
            <q-btn flat color="primary" label="Request new link" class="q-mt-lg" no-caps @click="token = null; $router.replace('/password-reset')" />
          </div>

          <div v-else-if="resetDone" class="text-center q-py-lg">
            <q-icon name="check_circle" size="64px" color="positive" />
            <div class="text-h6 q-mt-md">Password updated!</div>
            <q-btn unelevated color="primary" label="Sign in" class="q-mt-lg" no-caps @click="$router.push('/login')" />
          </div>

          <q-form v-else @submit.prevent="doConfirm" class="q-gutter-y-md">
            <div>
              <div class="sp-field-label">New password</div>
              <q-input v-model="newPassword" :type="showPwd ? 'text' : 'password'" outlined dense
                placeholder="At least 8 characters" :disable="loading" bg-color="white">
                <template v-slot:append>
                  <q-icon :name="showPwd ? 'visibility_off' : 'visibility'" color="grey-5"
                    class="cursor-pointer" @click="showPwd = !showPwd" />
                </template>
              </q-input>
            </div>
            <div>
              <div class="sp-field-label">Confirm password</div>
              <q-input v-model="confirmPassword" :type="showPwd ? 'text' : 'password'" outlined dense
                placeholder="Repeat new password" :disable="loading" bg-color="white" />
            </div>
            <q-btn type="submit" unelevated color="primary" label="Set new password"
              class="full-width sp-signin-btn" :loading="loading" no-caps />
          </q-form>
        </template>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { Notify } from 'quasar'
import api from '@/api/axios'

const route = useRoute()

const token = ref(route.query.token || null)
const email = ref('')
const newPassword = ref('')
const confirmPassword = ref('')
const showPwd = ref(false)
const loading = ref(false)
const requested = ref(false)
const resetDone = ref(false)
const tokenInvalid = ref(false)
const verifiedUser = ref(null)

onMounted(async () => {
  if (token.value) {
    try {
      const r = await api.get(`/auth/password-reset/verify/${token.value}`)
      if (!r.data.valid) {
        tokenInvalid.value = true
      } else {
        verifiedUser.value = r.data.username
      }
    } catch {
      tokenInvalid.value = true
    }
  }
})

async function doRequest() {
  if (!email.value) return
  loading.value = true
  try {
    await api.post('/auth/password-reset/request', { email: email.value })
    requested.value = true
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Request failed', color: 'negative' })
  } finally {
    loading.value = false
  }
}

async function doConfirm() {
  if (!newPassword.value || newPassword.value !== confirmPassword.value) {
    Notify.create({ message: 'Passwords do not match', color: 'warning' })
    return
  }
  if (newPassword.value.length < 8) {
    Notify.create({ message: 'Password must be at least 8 characters', color: 'warning' })
    return
  }
  loading.value = true
  try {
    await api.post('/auth/password-reset/confirm', {
      token: token.value,
      new_password: newPassword.value,
    })
    resetDone.value = true
  } catch (e) {
    const detail = e.response?.data?.detail || 'Reset failed'
    if (e.response?.status === 400) tokenInvalid.value = true
    else Notify.create({ message: detail, color: 'negative' })
  } finally {
    loading.value = false
  }
}
</script>

<style lang="scss" scoped>
.sp-login-wrap { display: flex; min-height: 100vh; background: var(--sp-content-bg, #f4f6fb); }
.sp-login-brand {
  flex: 0 0 420px;
  background: linear-gradient(145deg, #1a237e 0%, #283593 60%, #3949ab 100%);
  display: flex; align-items: center; justify-content: center; padding: 48px;
}
.sp-brand-inner { color: #fff; max-width: 280px; }
.sp-brand-logo {
  width: 80px; height: 80px; background: rgba(255,255,255,.12);
  border-radius: 20px; display: flex; align-items: center; justify-content: center; margin-bottom: 24px;
}
.sp-brand-name { font-size: 32px; font-weight: 300; letter-spacing: -0.5px; margin-bottom: 12px; strong { font-weight: 800; } }
.sp-brand-tagline { font-size: 15px; line-height: 1.5; color: rgba(255,255,255,.7); margin-bottom: 40px; }
.sp-login-form-panel { flex: 1; display: flex; align-items: center; justify-content: center; padding: 32px 24px; background: var(--sp-card-bg, #ffffff); }
.sp-login-form-inner { width: 100%; max-width: 380px; }
.sp-field-label { font-size: 13px; font-weight: 600; color: var(--sp-text-primary, #374151); margin-bottom: 6px; }
.sp-signin-btn { height: 44px; font-size: 15px; font-weight: 600; border-radius: 8px; margin-top: 8px; }
</style>
