<template>
  <div class="install-wrap">
    <div class="install-card">
      <div class="text-center q-mb-lg">
        <q-icon name="build_circle" size="56px" color="primary" />
        <div class="text-h4 text-weight-bold q-mt-md">Initial Setup</div>
        <div class="text-body1 text-grey-7 q-mt-sm">
          Create the first administrator and save the sysPass master password outside the application.
        </div>
      </div>

      <q-banner v-if="generatedMasterPassword" rounded class="bg-warning text-black q-mb-lg">
        <div class="text-subtitle1 text-weight-bold q-mb-sm">Generated master password</div>
        <div class="text-body1 text-weight-medium q-mb-sm">{{ generatedMasterPassword }}</div>
        <div class="text-caption">
          This password is shown only once. Store it securely before leaving this page.
        </div>
        <template #action>
          <q-btn
            color="dark"
            unelevated
            no-caps
            label="I saved it - continue to login"
            @click="continueToLogin"
          />
        </template>
      </q-banner>

      <q-form v-if="!installationComplete" @submit.prevent="onSubmit" class="q-gutter-md">
        <q-input v-model="form.username" outlined label="Admin username" :disable="loading" />
        <q-input v-model="form.name" outlined label="Display name" :disable="loading" />
        <q-input v-model="form.email" outlined type="email" label="Admin email" :disable="loading" />
        <q-input
          v-model="form.password"
          outlined
          :type="showPassword ? 'text' : 'password'"
          label="Login password"
          :disable="loading"
        >
          <template #append>
            <PasswordGenerator @use="form.password = $event; showPassword = true" />
            <q-icon
              :name="showPassword ? 'visibility_off' : 'visibility'"
              class="cursor-pointer"
              @click="showPassword = !showPassword"
            />
          </template>
        </q-input>
        <PasswordStrengthMeter :password="form.password" />

        <q-toggle
          v-model="generateMasterPassword"
          label="Generate the master password automatically"
          :disable="loading"
        />

        <q-input
          v-if="!generateMasterPassword"
          v-model="form.master_password"
          outlined
          :type="showMasterPassword ? 'text' : 'password'"
          label="Master password"
          :disable="loading"
        >
          <template #append>
            <PasswordGenerator @use="form.master_password = $event; showMasterPassword = true" />
            <q-icon
              :name="showMasterPassword ? 'visibility_off' : 'visibility'"
              class="cursor-pointer"
              @click="showMasterPassword = !showMasterPassword"
            />
          </template>
        </q-input>
        <PasswordStrengthMeter v-if="!generateMasterPassword" :password="form.master_password" />

        <q-btn
          type="submit"
          color="primary"
          unelevated
          no-caps
          class="full-width"
          :loading="loading"
          label="Complete installation"
        />
      </q-form>
    </div>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { Notify } from 'quasar'

import api from '@/api/axios'
import PasswordGenerator from '@/components/PasswordGenerator.vue'
import PasswordStrengthMeter from '@/components/PasswordStrengthMeter.vue'

const loading = ref(false)
const installationComplete = ref(false)
const generateMasterPassword = ref(true)
const generatedMasterPassword = ref('')
const showPassword = ref(false)
const showMasterPassword = ref(false)

const form = reactive({
  username: 'admin',
  name: '',
  email: '',
  password: '',
  master_password: '',
})

function errorMessage(error, fallback = 'Installation failed') {
  return error?.response?.data?.detail || error?.message || fallback
}

function continueToLogin() {
  window.location.replace('/login')
}

async function onSubmit() {
  if (!form.username || !form.password) {
    Notify.create({ message: 'Username and login password are required', color: 'warning' })
    return
  }
  if (!generateMasterPassword.value && !form.master_password) {
    Notify.create({ message: 'Enter a master password or enable automatic generation', color: 'warning' })
    return
  }

  loading.value = true
  try {
    const response = await api.post('/auth/install', {
      username: form.username,
      name: form.name || null,
      email: form.email || null,
      password: form.password,
      master_password: generateMasterPassword.value ? null : form.master_password,
      generate_master_password: generateMasterPassword.value,
    })

    generatedMasterPassword.value = response.data.master_password || ''
    installationComplete.value = true

    Notify.create({
      message: response.data.message,
      color: 'positive',
      timeout: 6000,
    })

    if (!generatedMasterPassword.value) {
      continueToLogin()
    }
  } catch (error) {
    const detail = String(errorMessage(error))
    if (error?.response?.status === 409) {
      Notify.create({ message: 'System is already installed. Redirecting to login.', color: 'info' })
      continueToLogin()
      return
    }
    Notify.create({ message: detail, color: 'negative', timeout: 5000 })
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.install-wrap {
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: 24px;
  background:
    radial-gradient(circle at top left, rgba(18, 138, 167, 0.18), transparent 35%),
    linear-gradient(135deg, #f5efe2 0%, #eef4f7 100%);
}

.install-card {
  width: min(100%, 560px);
  padding: 32px;
  border-radius: 24px;
  background: rgba(255, 255, 255, 0.92);
  box-shadow: 0 24px 60px rgba(23, 47, 64, 0.14);
  backdrop-filter: blur(10px);
}
</style>
