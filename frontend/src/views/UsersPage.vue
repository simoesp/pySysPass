<template>
  <q-page class="q-pa-md">
    <div class="row justify-between items-center q-mb-lg">
      <div>
        <h4 class="text-h4 text-weight-bold q-ma-none">Users</h4>
        <p class="text-body2 text-grey-6">Manage user accounts</p>
      </div>
      <q-btn color="primary" icon="add" label="New User" @click="openDialog()" />
    </div>

    <q-table
      :rows="users"
      :columns="columns"
      row-key="id"
      :loading="loading"
      flat
      bordered
    >
      <template v-slot:body-cell-is_admin="props">
        <q-td :props="props">
          <q-badge :color="props.row.is_admin ? 'negative' : 'grey-5'" :label="props.row.is_admin ? 'Admin' : 'User'" />
        </q-td>
      </template>
      <template v-slot:body-cell-is_active="props">
        <q-td :props="props">
          <q-badge :color="props.row.is_active ? 'positive' : 'grey-5'" :label="props.row.is_active ? 'Active' : 'Disabled'" />
        </q-td>
      </template>
      <template v-slot:body-cell-user_profile_id="props">
        <q-td :props="props">
          {{ profileName(props.row.user_profile_id) }}
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
      <q-card style="min-width: 480px">
        <q-card-section>
          <div class="text-h6">{{ editItem ? 'Edit User' : 'New User' }}</div>
        </q-card-section>
        <q-card-section class="q-pt-none q-gutter-md">
          <q-input v-model="form.username" label="Username *" outlined dense />
          <q-input v-model="form.email" label="Email" type="email" outlined dense />
          <q-input v-model="form.name" label="Full Name" outlined dense />
          <q-select
            v-model="form.user_profile_id"
            :options="profiles"
            option-label="name"
            option-value="id"
            label="User Profile"
            outlined
            dense
            emit-value
            map-options
            clearable
          />
          <q-input
            v-if="!editItem"
            v-model="form.password"
            label="Password *"
            type="password"
            outlined
            dense
          />
          <q-toggle v-model="form.is_admin" label="Administrator" />
          <q-toggle v-model="form.is_active" label="Active" />
          <CustomFieldsPanel v-if="showDialog" ref="cfPanel" :module-id="701" :item-id="editItem?.id ?? null" />
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

const users = ref([])
const profiles = ref([])
const loading = ref(false)
const saving = ref(false)
const showDialog = ref(false)
const editItem = ref(null)
const cfPanel = ref(null)
const form = ref({ username: '', email: '', name: '', password: '', is_admin: false, is_active: true, user_profile_id: null })

const columns = [
  { name: 'id', label: 'ID', field: 'id', sortable: true, align: 'left' },
  { name: 'username', label: 'Username', field: 'username', sortable: true, align: 'left' },
  { name: 'name', label: 'Full Name', field: 'name', align: 'left' },
  { name: 'email', label: 'Email', field: 'email', align: 'left' },
  { name: 'user_profile_id', label: 'Profile', field: 'user_profile_id', align: 'left' },
  { name: 'is_admin', label: 'Role', field: 'is_admin', align: 'center' },
  { name: 'is_active', label: 'Status', field: 'is_active', align: 'center' },
  { name: 'actions', label: 'Actions', field: 'actions', align: 'right' }
]

async function load() {
  loading.value = true
  try {
    const r = await api.get('/users')
    users.value = r.data
  } catch {
    Notify.create({ message: 'Failed to load users', color: 'negative' })
  } finally {
    loading.value = false
  }
}

function profileName(profileId) {
  return profiles.value.find(profile => profile.id === profileId)?.name || 'Default'
}

function openDialog(item = null) {
  editItem.value = item
  form.value = item
    ? { username: item.username, email: item.email || '', name: item.name || '', password: '', is_admin: item.is_admin || false, is_active: item.is_active !== false, user_profile_id: item.user_profile_id || null }
    : { username: '', email: '', name: '', password: '', is_admin: false, is_active: true, user_profile_id: null }
  showDialog.value = true
}

async function save() {
  if (!form.value.username) return Notify.create({ message: 'Username is required', color: 'warning' })
  if (!editItem.value && !form.value.password) return Notify.create({ message: 'Password is required', color: 'warning' })
  saving.value = true
  try {
    const payload = { ...form.value }
    if (editItem.value && !payload.password) delete payload.password
    let itemId
    if (editItem.value) {
      await api.put(`/users/${editItem.value.id}`, payload)
      itemId = editItem.value.id
    } else {
      const r = await api.post('/users', payload)
      itemId = r.data.id
    }
    await cfPanel.value?.save(itemId)
    Notify.create({ message: `User ${editItem.value ? 'updated' : 'created'}`, color: 'positive' })
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
    title: 'Delete User',
    message: `Delete user "${item.username}"? This cannot be undone.`,
    cancel: true,
    persistent: true
  }).onOk(async () => {
    try {
      await api.delete(`/users/${item.id}`)
      Notify.create({ message: 'User deleted', color: 'positive' })
      await load()
    } catch (e) {
      Notify.create({ message: e.response?.data?.detail || 'Failed to delete', color: 'negative' })
    }
  })
}

onMounted(async () => {
  await load()
  try {
    const response = await api.get('/user-profiles')
    profiles.value = response.data
  } catch {
    profiles.value = []
  }
})
</script>
