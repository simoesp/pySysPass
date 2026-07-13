<template>
  <q-page class="q-pa-md">
    <div class="row items-center q-mb-lg">
      <div>
        <h4 class="text-h4 text-weight-bold q-ma-none">Tracks</h4>
        <p class="text-body2 text-grey-6 q-ma-none">{{ total }} records</p>
      </div>
      <q-space />
      <q-toggle v-model="lockedOnly" label="Locked only" class="q-mr-sm" @update:model-value="load" />
      <q-btn flat icon="refresh" label="Refresh" @click="load" class="q-mr-sm" />
      <q-btn color="negative" icon="delete_sweep" label="Clear All" @click="confirmClear" />
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
      >
        <template v-slot:body-cell-is_locked="props">
          <q-td :props="props">
            <q-badge v-if="props.value" color="negative" label="Locked" />
            <q-badge v-else color="positive" label="OK" />
          </q-td>
        </template>
        <template v-slot:body-cell-time="props">
          <q-td :props="props">{{ fmtDate(props.value) }}</q-td>
        </template>
        <template v-slot:body-cell-time_unlock="props">
          <q-td :props="props">{{ props.value ? fmtDate(props.value) : '—' }}</q-td>
        </template>
        <template v-slot:body-cell-actions="props">
          <q-td :props="props" auto-width>
            <q-btn
              v-if="props.row.is_locked"
              flat dense round icon="lock_open" color="primary" size="sm"
              title="Unlock"
              @click="doUnlock(props.row.id)"
            />
            <q-btn
              flat dense round icon="delete" color="negative" size="sm"
              title="Delete"
              @click="doDelete(props.row.id)"
            />
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
const lockedOnly = ref(false)

const pagination = ref({ page: 1, rowsPerPage: 25, rowsNumber: 0, sortBy: null, descending: true })

const columns = [
  { name: 'is_locked',   label: 'Status',      field: 'is_locked',   align: 'center', sortable: false },
  { name: 'username',    label: 'User',         field: 'username',    align: 'left',   sortable: false },
  { name: 'ip',          label: 'IP',           field: 'ip',          align: 'left',   sortable: false },
  { name: 'source',      label: 'Source',       field: 'source',      align: 'left',   sortable: false },
  { name: 'time',        label: 'Time',         field: 'time',        align: 'left',   sortable: false },
  { name: 'time_unlock', label: 'Unlock After', field: 'time_unlock', align: 'left',   sortable: false },
  { name: 'actions',     label: '',             field: 'id',          align: 'right',  sortable: false },
]

function fmtDate(ts) {
  return ts ? new Date(ts * 1000).toLocaleString() : '—'
}

async function load() {
  loading.value = true
  const skip = (pagination.value.page - 1) * pagination.value.rowsPerPage
  const params = { skip, limit: pagination.value.rowsPerPage, locked_only: lockedOnly.value }
  try {
    const [dataRes, countRes] = await Promise.all([
      api.get('/tracks', { params }),
      api.get('/tracks/count', { params: { locked_only: lockedOnly.value } }),
    ])
    rows.value = dataRes.data ?? []
    total.value = countRes.data?.count ?? 0
    pagination.value.rowsNumber = total.value
  } catch (e) {
    const detail = e.response?.data?.detail ?? e.message ?? 'Unknown error'
    Notify.create({ message: `Failed to load tracks: ${detail}`, color: 'negative' })
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

async function doUnlock(id) {
  try {
    await api.post(`/tracks/${id}/unlock`)
    Notify.create({ message: 'Track unlocked', color: 'positive' })
    load()
  } catch (e) {
    Notify.create({ message: 'Failed to unlock', color: 'negative' })
  }
}

async function doDelete(id) {
  try {
    await api.delete(`/tracks/${id}`)
    Notify.create({ message: 'Track deleted', color: 'positive' })
    load()
  } catch (e) {
    Notify.create({ message: 'Failed to delete', color: 'negative' })
  }
}

function confirmClear() {
  Notify.create({
    message: 'Clear all track records?',
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
    const r = await api.delete('/tracks')
    Notify.create({ message: `Cleared ${r.data.deleted} records`, color: 'positive' })
    pagination.value.page = 1
    load()
  } catch (e) {
    Notify.create({ message: 'Failed to clear', color: 'negative' })
  }
}

onMounted(load)
</script>
