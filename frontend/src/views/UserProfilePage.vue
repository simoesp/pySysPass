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
  </q-page>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Notify } from 'quasar'
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

onMounted(load)
</script>

<style lang="scss" scoped>
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
