<template>
  <q-page class="q-pa-md">
    <div class="row items-center q-mb-lg">
      <div>
        <h4 class="text-h4 text-weight-bold q-ma-none">Event Log</h4>
        <p class="text-body2 text-grey-6 q-ma-none">{{ total }} events</p>
      </div>
      <q-space />
      <q-btn flat icon="refresh" label="Refresh" @click="load" class="q-mr-sm" />
      <q-btn color="negative" icon="delete_sweep" label="Clear All" @click="confirmClear" />
    </div>

    <!-- Filters -->
    <div class="row q-gutter-sm q-mb-md">
      <q-select
        v-model="filterLevel"
        :options="levelOptions"
        label="Level" outlined dense clearable emit-value map-options
        style="min-width:140px"
        @update:model-value="load"
      />
      <q-input v-model="filterLogin" label="User" outlined dense clearable debounce="400"
        style="min-width:180px" @update:model-value="load">
        <template v-slot:append><q-icon name="person" /></template>
      </q-input>
    </div>

    <q-card flat bordered>
      <q-table
        :rows="rows"
        :columns="columns"
        row-key="id"
        :loading="loading"
        flat dense
        :rows-per-page-options="[25, 50, 100]"
        @request="onRequest"
        v-model:pagination="pagination"
        binary-state-sort
      >
        <template v-slot:body-cell-level="props">
          <q-td :props="props">
            <q-badge :color="levelColor(props.value)" :label="props.value" />
          </q-td>
        </template>
        <template v-slot:body-cell-date="props">
          <q-td :props="props">{{ fmtDate(props.value) }}</q-td>
        </template>
        <template v-slot:body-cell-description="props">
          <q-td :props="props">
            <span class="ellipsis" style="max-width:320px;display:inline-block">{{ props.value || '—' }}</span>
          </q-td>
        </template>
      </q-table>
    </q-card>
  </q-page>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Notify } from 'quasar'
import api from '@/api/axios'

const rows = ref([])
const loading = ref(false)
const total = ref(0)
const filterLevel = ref(null)
const filterLogin = ref('')

const pagination = ref({ page: 1, rowsPerPage: 25, rowsNumber: 0, sortBy: null, descending: true })

const levelOptions = [
  { label: 'INFO',     value: 'INFO' },
  { label: 'NOTICE',   value: 'NOTICE' },
  { label: 'WARN',     value: 'WARN' },
  { label: 'ERROR',    value: 'ERROR' },
  { label: 'CRITICAL', value: 'CRITICAL' },
]

const columns = [
  { name: 'date',        label: 'Date',        field: 'date',        align: 'left',   sortable: false },
  { name: 'level',       label: 'Level',       field: 'level',       align: 'center', sortable: false },
  { name: 'login',       label: 'User',        field: 'login',       align: 'left',   sortable: false },
  { name: 'ip_address',  label: 'IP',          field: 'ip_address',  align: 'left',   sortable: false },
  { name: 'action',      label: 'Action',      field: 'action',      align: 'left',   sortable: false },
  { name: 'description', label: 'Description', field: 'description', align: 'left',   sortable: false },
]

function levelColor(level) {
  return { INFO: 'blue-6', NOTICE: 'teal', WARN: 'orange', ERROR: 'deep-orange', CRITICAL: 'negative' }[level] ?? 'grey'
}

function fmtDate(ts) {
  return ts ? new Date(ts * 1000).toLocaleString() : '—'
}

async function load() {
  loading.value = true
  const skip = (pagination.value.page - 1) * pagination.value.rowsPerPage
  const params = {
    skip,
    limit: pagination.value.rowsPerPage,
    ...(filterLevel.value ? { level: filterLevel.value } : {}),
    ...(filterLogin.value ? { login: filterLogin.value } : {}),
  }
  try {
    const [dataRes, countRes] = await Promise.all([
      api.get('/audit-log', { params }),
      api.get('/audit-log/count', { params: { level: params.level, login: params.login } }),
    ])
    rows.value = dataRes.data ?? []
    total.value = countRes.data?.count ?? 0
    pagination.value.rowsNumber = total.value
  } catch (e) {
    const detail = e.response?.data?.detail ?? e.message ?? 'Unknown error'
    Notify.create({ message: `Failed to load event log: ${detail}`, color: 'negative' })
    rows.value = []
    total.value = 0
  } finally {
    loading.value = false
  }
}

function onRequest(props) {
  pagination.value = props.pagination
  load()
}

function confirmClear() {
  Notify.create({
    message: 'Clear all event log entries?',
    color: 'negative',
    actions: [
      { label: 'Cancel', color: 'white' },
      { label: 'Clear', color: 'white', handler: doClear },
    ],
    timeout: 6000,
  })
}

async function doClear() {
  try {
    const r = await api.delete('/audit-log')
    Notify.create({ message: `Cleared ${r.data.deleted} entries`, color: 'positive' })
    pagination.value.page = 1
    load()
  } catch (e) {
    Notify.create({ message: 'Failed to clear', color: 'negative' })
  }
}

onMounted(load)
</script>
