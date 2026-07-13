<template>
  <q-page class="q-pa-md">
    <div class="row justify-between items-center q-mb-lg">
      <div>
        <h4 class="text-h4 text-weight-bold q-ma-none">Clients</h4>
        <p class="text-body2 text-grey-6">Manage clients associated with accounts</p>
      </div>
      <q-btn color="primary" icon="add" label="New Client" @click="openDialog()" />
    </div>

    <q-table
      :rows="clients"
      :columns="columns"
      row-key="id"
      :loading="loading"
      flat
      bordered
    >
      <template v-slot:body-cell-actions="props">
        <q-td :props="props" class="q-gutter-xs">
          <q-btn flat dense icon="edit" color="primary" @click="openDialog(props.row)" />
          <q-btn flat dense icon="delete" color="negative" @click="confirmDelete(props.row)" />
        </q-td>
      </template>
    </q-table>

    <q-dialog v-model="showDialog">
      <q-card style="min-width: 400px">
        <q-card-section>
          <div class="text-h6">{{ editItem ? 'Edit Client' : 'New Client' }}</div>
        </q-card-section>
        <q-card-section class="q-pt-none q-gutter-md">
          <q-input v-model="form.name" label="Name *" outlined dense />
          <q-input v-model="form.description" label="Description" outlined dense />
          <q-toggle v-model="form.isGlobal" label="Global (visible to all users)" />
          <CustomFieldsPanel v-if="showDialog" ref="cfPanel" :module-id="301" :item-id="editItem?.id ?? null" />
        </q-card-section>
        <q-card-actions align="right">
          <q-btn flat label="Cancel" v-close-popup />
          <q-btn color="primary" :label="editItem ? 'Save' : 'Create'" :loading="saving" @click="save" />
        </q-card-actions>
      </q-card>
    </q-dialog>
  </q-page>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Notify, Dialog } from 'quasar'
import api from '@/api/axios'
import CustomFieldsPanel from '@/components/CustomFieldsPanel.vue'

const clients = ref([])
const loading = ref(false)
const saving = ref(false)
const showDialog = ref(false)
const editItem = ref(null)
const cfPanel = ref(null)
const form = ref({ name: '', description: '', isGlobal: false })

const columns = [
  { name: 'id', label: 'ID', field: 'id', sortable: true, align: 'left' },
  { name: 'name', label: 'Name', field: 'name', sortable: true, align: 'left' },
  { name: 'description', label: 'Description', field: 'description', align: 'left' },
  { name: 'is_global', label: 'Global', field: 'is_global', align: 'center',
    format: v => v ? 'Yes' : 'No' },
  { name: 'actions', label: 'Actions', field: 'actions', align: 'right' }
]

async function load() {
  loading.value = true
  try {
    const r = await api.get('/clients')
    clients.value = r.data
  } catch {
    Notify.create({ message: 'Failed to load clients', color: 'negative' })
  } finally {
    loading.value = false
  }
}

function openDialog(item = null) {
  editItem.value = item
  form.value = item
    ? { name: item.name, description: item.description || '', isGlobal: item.is_global || false }
    : { name: '', description: '', isGlobal: false }
  showDialog.value = true
}

async function save() {
  if (!form.value.name) return Notify.create({ message: 'Name is required', color: 'warning' })
  saving.value = true
  try {
    const payload = { name: form.value.name, description: form.value.description, is_global: form.value.isGlobal }
    let itemId
    if (editItem.value) {
      await api.put(`/clients/${editItem.value.id}`, payload)
      itemId = editItem.value.id
    } else {
      const r = await api.post('/clients', payload)
      itemId = r.data.id
    }
    await cfPanel.value?.save(itemId)
    Notify.create({ message: `Client ${editItem.value ? 'updated' : 'created'}`, color: 'positive' })
    showDialog.value = false
    await load()
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Failed to save', color: 'negative' })
  } finally {
    saving.value = false
  }
}

function confirmDelete(item) {
  Dialog.create({
    title: 'Delete Client',
    message: `Delete "${item.name}"?`,
    cancel: true,
    persistent: true
  }).onOk(async () => {
    try {
      await api.delete(`/clients/${item.id}`)
      Notify.create({ message: 'Client deleted', color: 'positive' })
      await load()
    } catch (e) {
      Notify.create({ message: e.response?.data?.detail || 'Failed to delete', color: 'negative' })
    }
  })
}

onMounted(load)
</script>
