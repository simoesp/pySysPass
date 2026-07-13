<template>
  <q-page class="q-pa-md">
    <div class="row items-center q-mb-lg">
      <div>
        <h4 class="text-h4 text-weight-bold q-ma-none">Account Default Permissions</h4>
        <p class="text-body2 text-grey-6 q-ma-none">
          Configure default owners, privacy, and password policies applied to new accounts.
        </p>
      </div>
      <q-space />
      <q-btn color="primary" icon="add" label="New Preset" no-caps @click="openCreate()" />
    </div>

    <!-- Type filter -->
    <div class="q-mb-md row q-gutter-sm">
      <q-btn-toggle
        v-model="typeFilter"
        no-caps unelevated
        toggle-color="primary"
        :options="typeOptions"
        @update:model-value="load"
      />
    </div>

    <q-card flat bordered>
      <q-table
        :rows="rows"
        :columns="columns"
        row-key="id"
        :loading="loading"
        flat dense
        :rows-per-page-options="[25, 50]"
      >
        <template v-slot:body-cell-scope="props">
          <q-td :props="props">
            <span v-if="props.row.user_id">User #{{ props.row.user_id }}</span>
            <span v-else-if="props.row.user_group_id">Group #{{ props.row.user_group_id }}</span>
            <span v-else-if="props.row.user_profile_id">Profile #{{ props.row.user_profile_id }}</span>
            <q-badge v-else color="grey" label="Global" />
          </q-td>
        </template>
        <template v-slot:body-cell-fixed="props">
          <q-td :props="props">
            <q-icon :name="props.value ? 'lock' : 'lock_open'" :color="props.value ? 'negative' : 'grey-4'" />
          </q-td>
        </template>
        <template v-slot:body-cell-data="props">
          <q-td :props="props">
            <code class="text-caption">{{ JSON.stringify(props.value) }}</code>
          </q-td>
        </template>
        <template v-slot:body-cell-actions="props">
          <q-td :props="props" auto-width>
            <q-btn flat dense round icon="edit" color="primary" size="sm" @click="openEdit(props.row)" />
            <q-btn flat dense round icon="delete" color="negative" size="sm" @click="doDelete(props.row)" />
          </q-td>
        </template>
      </q-table>
    </q-card>

    <!-- Create / Edit dialog -->
    <q-dialog v-model="dialog" persistent>
      <q-card style="min-width: 520px">
        <q-card-section class="row items-center q-pb-none">
          <div class="text-h6">{{ editing ? 'Edit Preset' : 'New Preset' }}</div>
          <q-space />
          <q-btn icon="close" flat round dense v-close-popup />
        </q-card-section>
        <q-card-section class="q-gutter-md">
          <q-select v-if="!editing" v-model="form.type" :options="TYPES" label="Type" outlined dense emit-value map-options />
          <div v-else class="text-caption text-grey-6">Type: <strong>{{ form.type }}</strong></div>

          <div v-if="!editing" class="text-caption text-grey-7 q-mt-none">
            Scope — leave all blank for a global preset:
          </div>
          <div v-if="!editing" class="row q-gutter-sm">
            <q-input v-model.number="form.user_id" type="number" label="User ID" outlined dense class="col" clearable />
            <q-input v-model.number="form.user_group_id" type="number" label="Group ID" outlined dense class="col" clearable />
            <q-input v-model.number="form.user_profile_id" type="number" label="Profile ID" outlined dense class="col" clearable />
          </div>

          <q-input v-model.number="form.priority" type="number" label="Priority (higher = applied first)" outlined dense />
          <q-toggle v-model="form.fixed" label="Fixed (cannot be overridden by users)" />

          <div class="text-caption text-grey-7">Data (JSON payload for this preset type):</div>
          <q-input
            v-model="formDataStr"
            type="textarea"
            outlined dense autogrow
            label="data"
            :error="!!jsonError"
            :error-message="jsonError"
            @update:model-value="validateJson"
          />
        </q-card-section>
        <q-card-actions align="right">
          <q-btn flat label="Cancel" v-close-popup no-caps />
          <q-btn unelevated color="primary" :label="editing ? 'Save' : 'Create'" no-caps :loading="saving" @click="doSave" />
        </q-card-actions>
      </q-card>
    </q-dialog>
  </q-page>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Notify, Dialog } from 'quasar'
import api from '@/api/axios'

const TYPES = ['AccountPermission', 'AccountPrivate', 'Password', 'SessionTimeout']

const rows = ref([])
const loading = ref(false)
const dialog = ref(false)
const saving = ref(false)
const editing = ref(null)
const jsonError = ref('')
const typeFilter = ref(null)

const typeOptions = [
  { label: 'All', value: null },
  ...TYPES.map(t => ({ label: t, value: t })),
]

const columns = [
  { name: 'id', label: 'ID', field: 'id', align: 'left', sortable: true },
  { name: 'type', label: 'Type', field: 'type', align: 'left', sortable: true },
  { name: 'scope', label: 'Scope', field: 'scope', align: 'left' },
  { name: 'priority', label: 'Priority', field: 'priority', align: 'center', sortable: true },
  { name: 'fixed', label: 'Fixed', field: 'fixed', align: 'center' },
  { name: 'data', label: 'Data', field: 'data', align: 'left' },
  { name: 'actions', label: '', field: 'actions', align: 'right' },
]

const emptyForm = () => ({
  type: TYPES[0],
  user_id: null,
  user_group_id: null,
  user_profile_id: null,
  fixed: false,
  priority: 0,
  data: {},
})

const form = ref(emptyForm())
const formDataStr = ref('{}')

function validateJson(val) {
  try { JSON.parse(val); jsonError.value = '' } catch { jsonError.value = 'Invalid JSON' }
}

async function load() {
  loading.value = true
  try {
    const params = typeFilter.value ? { preset_type: typeFilter.value } : {}
    const r = await api.get('/item-presets', { params })
    rows.value = r.data
  } catch {
    Notify.create({ message: 'Failed to load presets', color: 'negative' })
  } finally {
    loading.value = false
  }
}

function openCreate() {
  editing.value = null
  form.value = emptyForm()
  formDataStr.value = '{}'
  jsonError.value = ''
  dialog.value = true
}

function openEdit(row) {
  editing.value = row.id
  form.value = { ...row }
  formDataStr.value = JSON.stringify(row.data, null, 2)
  jsonError.value = ''
  dialog.value = true
}

async function doSave() {
  if (jsonError.value) return
  let data
  try { data = JSON.parse(formDataStr.value) } catch { return }
  saving.value = true
  try {
    if (editing.value) {
      await api.put(`/item-presets/${editing.value}`, {
        fixed: form.value.fixed,
        priority: form.value.priority,
        data,
      })
    } else {
      await api.post('/item-presets', { ...form.value, data })
    }
    dialog.value = false
    Notify.create({ message: 'Saved', color: 'positive' })
    load()
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Save failed', color: 'negative' })
  } finally {
    saving.value = false
  }
}

function doDelete(row) {
  Dialog.create({
    title: 'Delete Preset',
    message: `Delete the "${row.type}" preset?`,
    cancel: true,
    persistent: true,
  }).onOk(async () => {
    try {
      await api.delete(`/item-presets/${row.id}`)
      Notify.create({ message: 'Deleted', color: 'positive' })
      load()
    } catch {
      Notify.create({ message: 'Delete failed', color: 'negative' })
    }
  })
}

onMounted(load)
</script>
