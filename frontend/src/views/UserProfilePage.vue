<template>
  <q-page class="q-pa-md">
    <div class="q-mb-lg">
      <h4 class="text-h4 text-weight-bold q-ma-none">My Profile</h4>
      <p class="text-body2 text-grey-6">Personal settings for {{ store.currentUser?.username }}</p>
    </div>

    <div class="row q-col-gutter-lg" style="max-width: 720px">

      <!-- ── Profile info ── -->
      <div class="col-12">
        <q-card flat bordered>
          <q-card-section>
            <div class="text-subtitle1 text-weight-medium q-mb-md">Profile</div>
            <div v-if="profile" class="q-gutter-md">
              <q-input v-model="profile.name" label="Display name" outlined dense />
              <q-input v-model="profile.email" label="Email" type="email" outlined dense />
              <div class="row justify-end">
                <q-btn color="primary" label="Save Profile" :loading="savingProfile" @click="saveProfile" />
              </div>
            </div>
            <div v-else class="text-center q-pa-md"><q-spinner-dots size="2rem" color="primary" /></div>
          </q-card-section>
        </q-card>
      </div>

      <!-- ── Change password ── -->
      <div class="col-12">
        <q-card flat bordered>
          <q-card-section>
            <div class="text-subtitle1 text-weight-medium q-mb-md">Change Password</div>
            <div class="q-gutter-md">
              <q-input v-model="pw.current" label="Current password" type="password" outlined dense />
              <q-input v-model="pw.new_pass" label="New password" type="password" outlined dense />
              <q-input v-model="pw.confirm" label="Confirm new password" type="password" outlined dense />
              <div class="row justify-end">
                <q-btn color="primary" label="Change Password" :loading="savingPw" @click="changePassword" />
              </div>
            </div>
          </q-card-section>
        </q-card>
      </div>

      <!-- ── Two-factor authentication ── -->
      <div class="col-12" v-if="tfa.mode !== 'disabled'">
        <q-card flat bordered>
          <q-card-section>
            <div class="row items-center q-mb-md">
              <div class="text-subtitle1 text-weight-medium">Two-Factor Authentication</div>
              <q-space />
              <q-badge :color="tfa.enrolled ? 'positive' : 'grey-5'"
                :label="tfa.enrolled ? 'Enabled' : 'Not enrolled'" />
            </div>

            <q-banner v-if="tfa.setup_required" dense class="bg-orange-1 text-orange-9 q-mb-md" rounded>
              <template v-slot:avatar><q-icon name="warning" color="orange-8" /></template>
              Your administrator requires two-factor authentication. Please enroll now.
            </q-banner>

            <div v-if="!tfa.enrolled" class="q-gutter-md">
              <div class="text-body2 text-grey-7">
                Protect your account with one-time codes from an authenticator app
                (Google Authenticator, Aegis, 1Password…).
              </div>
              <q-btn color="primary" label="Set up 2FA" icon="qr_code_2" no-caps @click="startTfaSetup" />
            </div>
            <div v-else class="q-gutter-md">
              <div class="text-body2 text-grey-7">
                A one-time code is required every time you log in.
              </div>
              <q-btn outline color="negative" label="Disable 2FA" no-caps @click="askDisableTfa" />
            </div>
          </q-card-section>
        </q-card>
      </div>

      <!-- ── Theme ── -->
      <div class="col-12">
        <q-card flat bordered>
          <q-card-section>
            <div class="text-subtitle1 text-weight-medium q-mb-md">Theme</div>
            <div class="sp-theme-grid">
              <button
                v-for="t in themes"
                :key="t.id"
                class="sp-theme-btn"
                :class="{ 'sp-theme-btn--active': activeTheme === t.id }"
                @click="selectTheme(t.id)"
              >
                <span class="sp-theme-swatch" :style="{ background: t.swatch }" />
                <span class="sp-theme-label">{{ t.label }}</span>
                <q-icon v-if="activeTheme === t.id" name="check" size="14px" color="primary" />
              </button>
            </div>
          </q-card-section>
        </q-card>
      </div>

    </div>

    <!-- ── 2FA setup dialog ── -->
    <q-dialog v-model="tfaDialog" persistent>
      <q-card style="min-width: 420px; max-width: 95vw">
        <q-card-section class="row items-center q-pb-none">
          <div class="text-h6">Set up two-factor authentication</div>
          <q-space /><q-btn flat round dense icon="close" v-close-popup />
        </q-card-section>

        <!-- Step 1: password -->
        <q-card-section v-if="tfaStep === 1" class="q-gutter-md">
          <div class="text-body2 text-grey-7">Confirm your password to begin.</div>
          <q-input v-model="tfaPassword" label="Password" type="password" outlined dense autofocus
            @keyup.enter="startTfaSecret" />
          <div class="row justify-end">
            <q-btn color="primary" label="Continue" :loading="tfaBusy" no-caps @click="startTfaSecret" />
          </div>
        </q-card-section>

        <!-- Step 2: scan + confirm -->
        <q-card-section v-else-if="tfaStep === 2" class="q-gutter-md">
          <div class="text-body2 text-grey-7">
            Scan the QR code with your authenticator app, or enter the secret manually,
            then type the 6-digit code to confirm.
          </div>
          <div class="row justify-center">
            <img v-if="tfaQrDataUrl" :src="tfaQrDataUrl" alt="2FA QR code" style="width: 200px; height: 200px" />
          </div>
          <q-input :model-value="tfaSecret" label="Secret (manual entry)" outlined dense readonly>
            <template v-slot:append>
              <q-btn flat dense icon="content_copy" @click="copyText(tfaSecret)" />
            </template>
          </q-input>
          <q-input v-model="tfaCode" label="6-digit code" outlined dense autofocus
            @keyup.enter="confirmTfa" />
          <div class="row justify-end">
            <q-btn color="primary" label="Verify and enable" :loading="tfaBusy" no-caps @click="confirmTfa" />
          </div>
        </q-card-section>

        <!-- Step 3: backup codes -->
        <q-card-section v-else class="q-gutter-md">
          <q-banner dense class="bg-green-1 text-green-9" rounded>
            <template v-slot:avatar><q-icon name="check_circle" color="positive" /></template>
            Two-factor authentication is enabled.
          </q-banner>
          <div class="text-body2 text-grey-7">
            Save these backup codes somewhere safe — each works once if you lose your device.
            They cannot be shown again.
          </div>
          <pre class="sp-backup-codes">{{ tfaBackupCodes.join('\n') }}</pre>
          <div class="row justify-between">
            <q-btn flat color="primary" icon="content_copy" label="Copy codes" no-caps
              @click="copyText(tfaBackupCodes.join('\n'))" />
            <q-btn color="primary" label="Done" no-caps v-close-popup />
          </div>
        </q-card-section>
      </q-card>
    </q-dialog>
  </q-page>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Notify, Dialog, copyToClipboard } from 'quasar'
import QRCode from 'qrcode'
import api from '@/api/axios'
import { useMainStore } from '@/stores'
import { themes, applyTheme, getSavedTheme } from '@/composables/useTheme'

const store = useMainStore()

const userId = ref(null)
const profile = ref(null)
const savingProfile = ref(false)

const pw = ref({ current: '', new_pass: '', confirm: '' })
const savingPw = ref(false)

const activeTheme = ref(getSavedTheme())

// ── Two-factor state ──────────────────────────────────────────────────────
const tfa = ref({ mode: 'disabled', enrolled: false, setup_required: false })
const tfaDialog = ref(false)
const tfaStep = ref(1)
const tfaBusy = ref(false)
const tfaPassword = ref('')
const tfaSecret = ref('')
const tfaQrDataUrl = ref('')
const tfaCode = ref('')
const tfaBackupCodes = ref([])

function selectTheme(id) {
  activeTheme.value = id
  applyTheme(id)
}

async function load() {
  try {
    // /auth/me returns the full user record for the token owner
    const me = await api.get('/auth/me')
    userId.value = me.data.id
    profile.value = { name: me.data.name || me.data.username, email: me.data.email }
    store.setUser({ id: me.data.id, username: me.data.username, is_admin: me.data.is_admin ?? false, permissions: me.data.permissions ?? null })
  } catch (e) {
    Notify.create({ message: 'Failed to load profile', color: 'negative' })
  }
}

async function saveProfile() {
  savingProfile.value = true
  try {
    await api.put(`/users/${userId.value}`, profile.value)
    Notify.create({ message: 'Profile saved', color: 'positive' })
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Failed to save', color: 'negative' })
  } finally {
    savingProfile.value = false
  }
}

async function changePassword() {
  if (pw.value.new_pass !== pw.value.confirm) {
    Notify.create({ message: 'Passwords do not match', color: 'negative' })
    return
  }
  savingPw.value = true
  try {
    await api.post(`/users/${userId.value}/password`, {
      current_password: pw.value.current,
      new_password: pw.value.new_pass,
    })
    pw.value = { current: '', new_pass: '', confirm: '' }
    Notify.create({ message: 'Password changed', color: 'positive' })
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Failed to change password', color: 'negative' })
  } finally {
    savingPw.value = false
  }
}

async function loadTfaStatus() {
  try {
    tfa.value = (await api.get('/2fa/status')).data
  } catch { /* endpoint requires auth; leave defaults */ }
}

function copyText(text) {
  copyToClipboard(text).then(() =>
    Notify.create({ message: 'Copied to clipboard', color: 'positive', timeout: 1200 }))
}

function startTfaSetup() {
  tfaStep.value = 1
  tfaPassword.value = ''
  tfaSecret.value = ''
  tfaQrDataUrl.value = ''
  tfaCode.value = ''
  tfaBackupCodes.value = []
  tfaDialog.value = true
}

async function startTfaSecret() {
  if (!tfaPassword.value) return
  tfaBusy.value = true
  try {
    const r = await api.post('/2fa/setup', { password: tfaPassword.value })
    tfaSecret.value = r.data.secret
    tfaQrDataUrl.value = await QRCode.toDataURL(r.data.provisioning_uri, { width: 200, margin: 1 })
    tfaStep.value = 2
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Failed to start 2FA setup', color: 'negative' })
  } finally {
    tfaBusy.value = false
  }
}

async function confirmTfa() {
  if (!tfaCode.value) return
  tfaBusy.value = true
  try {
    const r = await api.post('/2fa/enable', { code: tfaCode.value.trim() })
    tfaBackupCodes.value = r.data.backup_codes || []
    tfaStep.value = 3
    loadTfaStatus()
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Invalid code', color: 'negative' })
  } finally {
    tfaBusy.value = false
  }
}

function askDisableTfa() {
  Dialog.create({
    title: 'Disable two-factor authentication',
    message: 'Enter your password to disable 2FA.',
    prompt: { model: '', type: 'password', label: 'Password' },
    cancel: true,
    persistent: true,
  }).onOk(async (password) => {
    try {
      await api.post('/2fa/disable', { password })
      Notify.create({ message: '2FA disabled', color: 'positive' })
      loadTfaStatus()
    } catch (e) {
      Notify.create({ message: e.response?.data?.detail || 'Failed to disable 2FA', color: 'negative' })
    }
  })
}

onMounted(() => { load(); loadTfaStatus() })
</script>

<style lang="scss" scoped>
.sp-backup-codes {
  background: #f3f4f6;
  border-radius: 8px;
  padding: 12px 16px;
  font-family: monospace;
  font-size: 14px;
  line-height: 1.7;
  margin: 0;
}

.body--dark .sp-backup-codes {
  background: #1e293b;
}

.sp-theme-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.sp-theme-btn {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border: 1.5px solid #e5e7eb;
  border-radius: 8px;
  background: #fff;
  cursor: pointer;
  font-size: 13px;
  font-weight: 500;
  color: #374151;
  transition: border-color .15s, box-shadow .15s;

  &:hover {
    border-color: #9ca3af;
    box-shadow: 0 1px 4px rgba(0,0,0,.08);
  }

  &--active {
    border-color: var(--q-primary, #1976d2);
    box-shadow: 0 0 0 2px rgba(25, 118, 210, .15);
  }
}

.body--dark .sp-theme-btn {
  background: #1e293b;
  border-color: #334155;
  color: #e2e8f0;

  &:hover { border-color: #64748b; }
  &--active { border-color: var(--q-primary, #5c9dff); }
}

.sp-theme-swatch {
  width: 18px;
  height: 18px;
  border-radius: 50%;
  flex-shrink: 0;
  box-shadow: inset 0 1px 2px rgba(0,0,0,.2);
}
</style>
