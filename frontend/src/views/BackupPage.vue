<template>
  <q-page class="q-pa-md">
    <div class="row items-center q-mb-lg">
      <div>
        <h4 class="text-h4 text-weight-bold q-ma-none">Backup</h4>
        <p class="text-body2 text-grey-6 q-ma-none">
          Create and manage database + data directory backups.
        </p>
      </div>
      <q-space />
      <q-btn
        color="primary" icon="backup" label="Create Backup"
        no-caps :loading="creating" @click="doCreate"
      />
    </div>

    <q-banner class="bg-warning text-dark q-mb-md">
      Restore requires a maintenance window. Stop all applications sharing the database and
      follow the offline recovery procedure before restarting them.
    </q-banner>
    <q-card flat bordered>
      <q-table
        :rows="backups"
        :columns="columns"
        row-key="filename"
        :loading="loading"
        flat dense
        :rows-per-page-options="[25, 50]"
        no-data-label="No backups yet — click Create Backup to make one."
      >
        <template v-slot:body-cell-size="props">
          <q-td :props="props">{{ formatSize(props.value) }}</q-td>
        </template>
        <template v-slot:body-cell-db_included="props">
          <q-td :props="props">
            <q-icon
              :name="props.value ? 'check_circle' : 'remove_circle'"
              :color="props.value ? 'positive' : 'grey-4'"
            />
          </q-td>
        </template>
        <template v-slot:body-cell-actions="props">
          <q-td :props="props" auto-width>
            <q-btn
              flat dense round icon="download" color="primary" size="sm"
              @click="doDownload(props.row.filename)"
            >
              <q-tooltip>Download</q-tooltip>
            </q-btn>
            <q-btn
              flat dense round icon="delete" color="negative" size="sm"
              @click="doDelete(props.row)"
            >
              <q-tooltip>Delete</q-tooltip>
            </q-btn>
          </q-td>
        </template>
      </q-table>
    </q-card>
  </q-page>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Notify, Dialog } from 'quasar'
import api from '@/api/axios'

const backups = ref([])
const loading = ref(false)
const creating = ref(false)

const columns = [
  { name: 'filename', label: 'Filename', field: 'filename', align: 'left', sortable: true },
  { name: 'created_at', label: 'Created', field: 'created_at', align: 'left', sortable: true },
  { name: 'size', label: 'Size', field: 'size', align: 'right', sortable: true },
  { name: 'db_included', label: 'DB Dump', field: 'db_included', align: 'center' },
  { name: 'actions', label: '', field: 'actions', align: 'right' },
]

function formatSize(bytes) {
  if (bytes == null) return '—'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`
}

async function load() {
  loading.value = true
  try {
    const r = await api.get('/backup/')
    backups.value = r.data
  } catch {
    Notify.create({ message: 'Failed to load backups', color: 'negative' })
  } finally {
    loading.value = false
  }
}

async function doCreate() {
  creating.value = true
  try {
    const r = await api.post('/backup/create?include_db=true')
    Notify.create({
      message: `Backup created: ${r.data.filename}`,
      color: 'positive',
    })
    load()
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Backup failed', color: 'negative' })
  } finally {
    creating.value = false
  }
}

function doDownload(filename) {
  const token = localStorage.getItem('auth_token')
  const url = `/api/v1/backup/${encodeURIComponent(filename)}/download`
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  // Attach auth header via fetch + blob for security
  fetch(url, { headers: { Authorization: `Bearer ${token}` } })
    .then(r => r.blob())
    .then(blob => {
      const blobUrl = URL.createObjectURL(blob)
      a.href = blobUrl
      a.click()
      URL.revokeObjectURL(blobUrl)
    })
    .catch(() => Notify.create({ message: 'Download failed', color: 'negative' }))
}

function doDelete(row) {
  Dialog.create({
    title: 'Delete Backup',
    message: `Delete ${row.filename}?`,
    cancel: true,
    persistent: true,
  }).onOk(async () => {
    try {
      await api.delete(`/backup/${encodeURIComponent(row.filename)}`)
      Notify.create({ message: 'Backup deleted', color: 'positive' })
      load()
    } catch {
      Notify.create({ message: 'Delete failed', color: 'negative' })
    }
  })
}

onMounted(load)
</script>
