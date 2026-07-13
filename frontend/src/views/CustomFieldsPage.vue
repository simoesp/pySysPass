<template>
  <q-page class="q-pa-md">
    <div class="row items-center q-mb-lg">
      <div>
        <h4 class="text-h4 text-weight-bold q-ma-none">Custom Fields</h4>
        <p class="text-body2 text-grey-6 q-ma-none">{{ rows.length }} definitions</p>
      </div>
      <q-space />
      <q-btn unelevated color="primary" icon="add" label="New field" no-caps @click="openCreate" />
    </div>

    <q-card flat bordered>
      <q-table
        :rows="rows"
        :columns="columns"
        row-key="id"
        :loading="loading"
        flat dense
        :rows-per-page-options="[0]"
        hide-pagination
      >
        <template v-slot:body-cell-module_id="props">
          <q-td :props="props">
            <q-badge :color="moduleColor(props.value)" :label="moduleName(props.value)" />
          </q-td>
        </template>
        <template v-slot:body-cell-type_name="props">
          <q-td :props="props">
            <q-chip dense size="sm" :icon="typeIcon(props.value)" class="q-ma-none">
              {{ props.row.type_text || props.value }}
            </q-chip>
          </q-td>
        </template>
        <template v-slot:body-cell-is_required="props">
          <q-td :props="props" class="text-center">
            <q-icon :name="props.value ? 'check_circle' : 'radio_button_unchecked'"
              :color="props.value ? 'positive' : 'grey-4'" size="18px" />
          </q-td>
        </template>
        <template v-slot:body-cell-is_show="props">
          <q-td :props="props" class="text-center">
            <q-icon :name="props.value ? 'check_circle' : 'radio_button_unchecked'"
              :color="props.value ? 'positive' : 'grey-4'" size="18px" />
          </q-td>
        </template>
        <template v-slot:body-cell-is_encrypted="props">
          <q-td :props="props" class="text-center">
            <q-icon :name="props.value ? 'lock' : ''" :color="props.value ? 'warning' : ''" size="18px" />
          </q-td>
        </template>
        <template v-slot:body-cell-actions="props">
          <q-td :props="props" auto-width>
            <q-btn flat dense round icon="edit" size="sm" color="primary" @click="openEdit(props.row)" />
            <q-btn flat dense round icon="delete" size="sm" color="negative" @click="confirmDelete(props.row)" />
          </q-td>
        </template>
      </q-table>
    </q-card>

    <!-- Create / Edit dialog -->
    <q-dialog v-model="showDialog" persistent>
      <q-card style="min-width:480px; max-width:95vw">
        <q-card-section class="row items-center q-pb-none">
          <div class="text-h6">{{ editing ? 'Edit field' : 'New field' }}</div>
          <q-space /><q-btn flat round dense icon="close" v-close-popup />
        </q-card-section>

        <q-card-section class="q-gutter-y-sm q-pt-md">
          <q-input v-model="form.name" label="Name *" outlined dense autofocus />
          <q-input v-model="form.help" label="Description / help text" outlined dense />

          <div class="row q-gutter-sm">
            <q-select v-model="form.type_id" :options="typeOpts" option-label="label"
              option-value="value" label="Field type *" outlined dense emit-value map-options class="col" />
            <q-select v-model="form.module_id" :options="moduleOpts" option-label="label"
              option-value="value" label="Applies to" outlined dense emit-value map-options class="col" />
          </div>

          <div class="row q-gutter-md q-mt-xs">
            <q-checkbox v-model="form.is_required"  label="Required" dense />
            <q-checkbox v-model="form.is_show"      label="Show in account list" dense />
            <q-checkbox v-model="form.is_encrypted" label="Encrypted" dense :disable="editing" />
          </div>
        </q-card-section>

        <q-card-actions align="right" class="q-pa-md">
          <q-btn flat label="Cancel" v-close-popup />
          <q-btn unelevated color="primary" :label="editing ? 'Save' : 'Create'"
            :loading="saving" no-caps @click="save" />
        </q-card-actions>
      </q-card>
    </q-dialog>
  </q-page>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Notify } from 'quasar'
import api from '@/api/axios'

const rows    = ref([])
const loading = ref(false)
const saving  = ref(false)
const showDialog = ref(false)
const editing    = ref(null)   // null = create, object = edit

const fieldTypes = ref([])

const form = ref(blankForm())
function blankForm() {
  return { name: '', help: '', type_id: 1, module_id: 1,
           is_required: false, is_show: true, is_encrypted: false }
}

const columns = [
  { name: 'name',         label: 'Name',          field: 'name',         align: 'left',   sortable: true },
  { name: 'module_id',    label: 'Applies to',    field: 'module_id',    align: 'left',   sortable: true },
  { name: 'type_name',    label: 'Type',          field: 'type_name',    align: 'left',   sortable: true },
  { name: 'is_required',  label: 'Required',      field: 'is_required',  align: 'center', sortable: false },
  { name: 'is_show',      label: 'In list',       field: 'is_show',      align: 'center', sortable: false },
  { name: 'is_encrypted', label: 'Encrypted',     field: 'is_encrypted', align: 'center', sortable: false },
  { name: 'help',         label: 'Help',          field: 'help',         align: 'left',   sortable: false },
  { name: 'actions',      label: '',              field: 'id',           align: 'right',  sortable: false },
]

const MODULE_LABELS = { 1: 'Accounts', 101: 'Categories', 301: 'Clients', 701: 'Users', 801: 'User Groups' }
const MODULE_COLORS = { 1: 'primary', 101: 'teal', 301: 'purple', 701: 'orange', 801: 'indigo' }
const moduleOpts = [
  { label: 'Accounts',    value: 1 },
  { label: 'Categories',  value: 101 },
  { label: 'Clients',     value: 301 },
  { label: 'Users',       value: 701 },
  { label: 'User Groups', value: 801 },
]
function moduleName(id) { return MODULE_LABELS[id] ?? `Module ${id}` }
function moduleColor(id) { return MODULE_COLORS[id] ?? 'grey' }

const TYPE_ICONS = {
  text: 'short_text', password: 'lock', date: 'event', number: 'tag',
  email: 'email', telephone: 'phone', url: 'link', color: 'palette',
  wiki: 'menu_book', textarea: 'notes',
}
function typeIcon(name) { return TYPE_ICONS[name] ?? 'tune' }

const typeOpts = ref([])

async function load() {
  loading.value = true
  try {
    const [defsRes, typesRes] = await Promise.all([
      api.get('/custom-fields/definitions'),
      api.get('/custom-fields/types'),
    ])
    rows.value = defsRes.data
    fieldTypes.value = typesRes.data
    typeOpts.value = typesRes.data.map(t => ({ label: t.text || t.name, value: t.id }))
  } catch {
    Notify.create({ message: 'Failed to load custom fields', color: 'negative' })
  } finally {
    loading.value = false
  }
}

function openCreate() {
  editing.value = null
  form.value = blankForm()
  if (typeOpts.value.length) form.value.type_id = typeOpts.value[0].value
  showDialog.value = true
}

function openEdit(row) {
  editing.value = row
  form.value = {
    name: row.name,
    help: row.help ?? '',
    type_id: row.type_id,
    module_id: row.module_id,
    is_required: row.is_required,
    is_show: row.is_show,
    is_encrypted: row.is_encrypted,
  }
  showDialog.value = true
}

async function save() {
  if (!form.value.name?.trim()) {
    Notify.create({ message: 'Name is required', color: 'warning' })
    return
  }
  saving.value = true
  try {
    const payload = {
      name: form.value.name.trim(),
      description: form.value.help || null,
      type_id: form.value.type_id,
      module_id: form.value.module_id,
      is_required: form.value.is_required,
      is_show: form.value.is_show,
      is_encrypted: form.value.is_encrypted,
    }
    if (editing.value) {
      const r = await api.put(`/custom-fields/definitions/${editing.value.id}`, payload)
      const idx = rows.value.findIndex(r2 => r2.id === editing.value.id)
      if (idx >= 0) rows.value[idx] = r.data
    } else {
      const r = await api.post('/custom-fields/definitions', payload)
      rows.value.push(r.data)
    }
    showDialog.value = false
    Notify.create({ message: editing.value ? 'Field updated' : 'Field created', color: 'positive' })
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail ?? 'Save failed', color: 'negative' })
  } finally {
    saving.value = false
  }
}

function confirmDelete(row) {
  Notify.create({
    message: `Delete field "${row.name}"?`,
    color: 'negative',
    actions: [
      { label: 'Cancel', color: 'white' },
      { label: 'Delete', color: 'white', handler: () => doDelete(row) },
    ],
    timeout: 6000,
  })
}

async function doDelete(row) {
  try {
    await api.delete(`/custom-fields/definitions/${row.id}`)
    rows.value = rows.value.filter(r => r.id !== row.id)
    Notify.create({ message: 'Field deleted', color: 'positive' })
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail ?? 'Delete failed', color: 'negative' })
  }
}

onMounted(load)
</script>
