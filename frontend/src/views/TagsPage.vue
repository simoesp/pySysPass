<template>
  <q-page class="q-pa-md">
    <div class="row justify-between items-center q-mb-lg">
      <div>
        <h4 class="text-h4 text-weight-bold q-ma-none">Tags</h4>
        <p class="text-body2 text-grey-6">Manage tags for labelling accounts</p>
      </div>
      <q-btn color="primary" icon="add" label="New Tag" @click="openDialog()" />
    </div>

    <q-table
      :rows="tags"
      :columns="columns"
      row-key="id"
      :loading="loading"
      flat
      bordered
    >
      <template v-slot:body-cell-name="props">
        <q-td :props="props">
          <q-chip :color="props.row.color || 'primary'" text-color="white" dense>
            {{ props.row.name }}
          </q-chip>
        </q-td>
      </template>
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
          <div class="text-h6">{{ editItem ? 'Edit Tag' : 'New Tag' }}</div>
        </q-card-section>
        <q-card-section class="q-pt-none q-gutter-md">
          <q-input v-model="form.name" label="Name *" outlined dense />
          <div class="row items-center q-gutter-sm">
            <div class="text-body2">Color:</div>
            <q-color v-model="form.color" no-header no-footer default-value="#1976D2" />
          </div>
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

const tags = ref([])
const loading = ref(false)
const saving = ref(false)
const showDialog = ref(false)
const editItem = ref(null)
const form = ref({ name: '', color: '#1976D2' })

const columns = [
  { name: 'id', label: 'ID', field: 'id', sortable: true, align: 'left' },
  { name: 'name', label: 'Name', field: 'name', sortable: true, align: 'left' },
  { name: 'actions', label: 'Actions', field: 'actions', align: 'right' }
]

async function load() {
  loading.value = true
  try {
    const r = await api.get('/tags')
    tags.value = r.data
  } catch {
    Notify.create({ message: 'Failed to load tags', color: 'negative' })
  } finally {
    loading.value = false
  }
}

function openDialog(item = null) {
  editItem.value = item
  form.value = item ? { name: item.name, color: item.color || '#1976D2' } : { name: '', color: '#1976D2' }
  showDialog.value = true
}

async function save() {
  if (!form.value.name) return Notify.create({ message: 'Name is required', color: 'warning' })
  saving.value = true
  try {
    if (editItem.value) {
      await api.put(`/tags/${editItem.value.id}`, form.value)
    } else {
      await api.post('/tags', form.value)
    }
    Notify.create({ message: `Tag ${editItem.value ? 'updated' : 'created'}`, color: 'positive' })
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
    title: 'Delete Tag',
    message: `Delete tag "${item.name}"?`,
    cancel: true,
    persistent: true
  }).onOk(async () => {
    try {
      await api.delete(`/tags/${item.id}`)
      Notify.create({ message: 'Tag deleted', color: 'positive' })
      await load()
    } catch (e) {
      Notify.create({ message: e.response?.data?.detail || 'Failed to delete', color: 'negative' })
    }
  })
}

onMounted(load)
</script>
