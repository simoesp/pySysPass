<template>
  <q-page class="q-pa-md">
    <div class="row items-center q-mb-lg">
      <div>
        <h4 class="text-h4 text-weight-bold q-ma-none">API Authorizations</h4>
        <p class="text-body2 text-grey-6 q-ma-none">Manage API access tokens</p>
      </div>
      <q-space />
      <q-btn color="primary" icon="add" label="New Token" @click="openCreate" />
    </div>

    <!-- Token table -->
    <q-card flat bordered>
      <q-table
        :rows="tokens"
        :columns="columns"
        row-key="id"
        :loading="loading"
        flat
        dense
        :rows-per-page-options="[15, 25, 50]"
      >
        <template v-slot:body-cell-token="props">
          <q-td :props="props">
            <div class="row items-center no-wrap q-gutter-xs text-grey-6">
              <code class="sp-token-code">••••••••</code>
              <q-tooltip>The secret is shown only when a token is created or regenerated</q-tooltip>
            </div>
          </q-td>
        </template>

        <template v-slot:body-cell-has_vault="props">
          <q-td :props="props">
            <q-icon :name="props.value ? 'lock' : 'lock_open'"
              :color="props.value ? 'positive' : 'grey-5'"
              size="18px">
              <q-tooltip>{{ props.value ? 'Master password stored' : 'No master password' }}</q-tooltip>
            </q-icon>
          </q-td>
        </template>

        <template v-slot:body-cell-start_date="props">
          <q-td :props="props">{{ fmtDate(props.value) }}</q-td>
        </template>

        <template v-slot:body-cell-actions="props">
          <q-td :props="props" auto-width>
            <q-btn flat round dense size="sm" icon="refresh" color="primary"
              @click="regenerate(props.row)">
              <q-tooltip>Regenerate token</q-tooltip>
            </q-btn>
            <q-btn flat round dense size="sm" icon="delete" color="negative"
              @click="confirmDelete(props.row)">
              <q-tooltip>Delete token</q-tooltip>
            </q-btn>
          </q-td>
        </template>
      </q-table>
    </q-card>

    <!-- Create dialog -->
    <q-dialog v-model="showCreate" persistent>
      <q-card style="min-width: 420px">
        <q-card-section class="text-h6">New API Token</q-card-section>
        <q-card-section class="q-gutter-md">
          <q-select
            v-model="form.user_id"
            :options="userOptions"
            label="User *"
            outlined dense
            emit-value map-options
          />
          <q-select
            v-model="form.action_id"
            :options="actionOptions"
            label="Action *"
            outlined dense
            emit-value map-options
            use-input hide-selected fill-input input-debounce="0"
            @filter="filterActions"
          />
        </q-card-section>
        <q-card-actions align="right" class="q-pa-md">
          <q-btn flat label="Cancel" v-close-popup />
          <q-btn color="primary" label="Create" :loading="creating"
            :disable="!form.user_id || !form.action_id"
            @click="createToken" />
        </q-card-actions>
      </q-card>
    </q-dialog>

    <!-- Newly created token reveal -->
    <q-dialog v-model="showNewToken">
      <q-card style="min-width: 480px">
        <q-card-section class="text-h6 text-positive row items-center gap-sm">
          <q-icon name="check_circle" />
          Token created
        </q-card-section>
        <q-card-section>
          <p class="text-body2 text-grey-7">Copy this token now — it will be masked afterwards.</p>
          <div class="sp-new-token-box q-pa-sm rounded-borders">
            <code class="text-body2" style="word-break:break-all">{{ newToken }}</code>
          </div>
        </q-card-section>
        <q-card-actions align="right" class="q-pa-md">
          <q-btn color="primary" icon="content_copy" label="Copy & Close" @click="copyAndClose" />
        </q-card-actions>
      </q-card>
    </q-dialog>
  </q-page>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Notify, copyToClipboard } from 'quasar'
import api from '@/api/axios'

const tokens = ref([])
const loading = ref(false)

const showCreate = ref(false)
const creating = ref(false)
const form = ref({ user_id: null, action_id: null })

const showNewToken = ref(false)
const newToken = ref('')

const allActionOptions = ref([])
const actionOptions = ref([])
const userOptions = ref([])

const columns = [
  { name: 'username', label: 'User', field: 'username', align: 'left', sortable: true },
  { name: 'action_label', label: 'Action', field: 'action_label', align: 'left', sortable: true },
  { name: 'token', label: 'Token', field: 'token', align: 'left' },
  { name: 'has_vault', label: 'Vault', field: 'has_vault', align: 'center' },
  { name: 'start_date', label: 'Created', field: 'start_date', align: 'left', sortable: true },
  { name: 'actions', label: '', field: 'actions', align: 'right' },
]

function fmtDate(ts) {
  if (!ts) return '—'
  return new Date(ts * 1000).toLocaleString()
}

async function copy(token) {
  await copyToClipboard(token)
  Notify.create({ message: 'Token copied', color: 'positive', icon: 'content_copy', timeout: 1500 })
}

function filterActions(val, update) {
  update(() => {
    const v = val.toLowerCase()
    actionOptions.value = v
      ? allActionOptions.value.filter(o => o.label.toLowerCase().includes(v))
      : [...allActionOptions.value]
  })
}

async function load() {
  loading.value = true
  try {
    const [tokensRes, actionsRes, usersRes] = await Promise.all([
      api.get('/auth-tokens'),
      api.get('/auth-tokens/actions'),
      api.get('/users'),
    ])
    tokens.value = tokensRes.data
    allActionOptions.value = actionsRes.data.map(a => ({ label: a.label, value: a.id }))
    actionOptions.value = [...allActionOptions.value]
    userOptions.value = usersRes.data.map(u => ({ label: u.username, value: u.id }))
  } catch (e) {
    Notify.create({ message: 'Failed to load', color: 'negative' })
  } finally {
    loading.value = false
  }
}

function openCreate() {
  form.value = { user_id: null, action_id: null }
  showCreate.value = true
}

async function createToken() {
  creating.value = true
  try {
    const r = await api.post('/auth-tokens', form.value)
    tokens.value.unshift(r.data)
    showCreate.value = false
    newToken.value = r.data.token
    showNewToken.value = true
    Notify.create({ message: 'Token created', color: 'positive' })
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Failed to create', color: 'negative' })
  } finally {
    creating.value = false
  }
}

async function copyAndClose() {
  await copy(newToken.value)
  showNewToken.value = false
}

async function regenerate(row) {
  try {
    const r = await api.post(`/auth-tokens/${row.id}/regenerate`)
    newToken.value = r.data.token
    showNewToken.value = true
    Notify.create({ message: 'Token regenerated', color: 'positive' })
    await load()
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Failed to regenerate', color: 'negative' })
  }
}

function confirmDelete(row) {
  Notify.create({
    message: `Delete token for "${row.action_label}"?`,
    color: 'negative',
    actions: [
      { label: 'Cancel', color: 'white' },
      { label: 'Delete', color: 'white', handler: () => deleteToken(row) },
    ],
    timeout: 6000,
  })
}

async function deleteToken(row) {
  try {
    await api.delete(`/auth-tokens/${row.id}`)
    tokens.value = tokens.value.filter(t => t.id !== row.id)
    Notify.create({ message: 'Token deleted', color: 'positive' })
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Failed to delete', color: 'negative' })
  }
}

onMounted(load)
</script>

<style lang="scss" scoped>
.sp-token-code {
  font-family: 'Courier New', monospace;
  font-size: 12px;
  background: var(--q-grey-2, #f5f5f5);
  padding: 2px 6px;
  border-radius: 4px;
}

.sp-new-token-box {
  background: #f5f9ff;
  border: 1px solid #90caf9;
}
</style>
