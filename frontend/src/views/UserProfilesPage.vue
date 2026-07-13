<template>
  <q-page class="q-pa-md">
    <div class="row justify-between items-center q-mb-lg">
      <div>
        <h4 class="text-h4 text-weight-bold q-ma-none">User Profiles</h4>
        <p class="text-body2 text-grey-6">Manage reusable permission bundles for users</p>
      </div>
      <q-btn color="primary" icon="add" label="New Profile" @click="openDialog()" />
    </div>

    <q-table
      :rows="profiles"
      :columns="columns"
      row-key="id"
      :loading="loading"
      flat
      bordered
    >
      <template v-slot:body-cell-permissions="props">
        <q-td :props="props">
          <div class="row q-gutter-xs">
            <q-badge
              v-for="item in enabledPermissions(props.row.permissions).slice(0, 4)"
              :key="item"
              color="blue-1"
              text-color="primary"
            >
              {{ permissionLabel(item) }}
            </q-badge>
            <q-badge
              v-if="enabledPermissions(props.row.permissions).length > 4"
              color="grey-3"
              text-color="grey-8"
            >
              +{{ enabledPermissions(props.row.permissions).length - 4 }}
            </q-badge>
          </div>
        </q-td>
      </template>
      <template v-slot:body-cell-assigned_user_count="props">
        <q-td :props="props">
          <q-badge color="teal-1" text-color="teal-8" :label="props.row.assigned_user_count" />
        </q-td>
      </template>
      <template v-slot:body-cell-actions="props">
        <q-td :props="props" class="q-gutter-xs">
          <q-btn flat dense icon="edit" color="primary" @click="openDialog(props.row)" />
          <q-btn flat dense icon="delete" color="negative" @click="confirmDelete(props.row)" />
        </q-td>
      </template>
    </q-table>

    <q-dialog v-model="showDialog" maximized persistent>
      <q-card>
        <q-card-section class="row items-center">
          <div class="text-h6">{{ editItem ? 'Edit Profile' : 'New Profile' }}</div>
          <q-space />
          <q-btn flat round icon="close" v-close-popup />
        </q-card-section>

        <q-separator />

        <q-card-section class="q-gutter-lg">
          <div class="row q-col-gutter-md">
            <div class="col-12 col-md-6">
              <q-input v-model="form.name" label="Name *" outlined dense />
            </div>
          </div>

          <div class="row q-col-gutter-lg">
            <div v-for="section in permissionSections" :key="section.title" class="col-12 col-md-6 col-lg-4">
              <q-card flat bordered>
                <q-card-section class="text-subtitle2 text-weight-medium">
                  {{ section.title }}
                </q-card-section>
                <q-separator />
                <q-card-section class="q-gutter-sm">
                  <q-toggle
                    v-for="field in section.fields"
                    :key="field.key"
                    v-model="form.permissions[field.key]"
                    :label="field.label"
                  />
                </q-card-section>
              </q-card>
            </div>
          </div>
        </q-card-section>

        <q-card-actions align="right" class="q-pa-md">
          <q-btn flat label="Cancel" v-close-popup />
          <q-btn color="primary" :label="editItem ? 'Save' : 'Create'" :loading="saving" @click="save" />
        </q-card-actions>
      </q-card>
    </q-dialog>
  </q-page>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Dialog, Notify } from 'quasar'
import api from '@/api/axios'

const profiles = ref([])
const loading = ref(false)
const saving = ref(false)
const showDialog = ref(false)
const editItem = ref(null)

const permissionSections = [
  {
    title: 'Accounts',
    fields: [
      { key: 'acc_view', label: 'View accounts' },
      { key: 'acc_view_pass', label: 'View passwords' },
      { key: 'acc_view_history', label: 'View history' },
      { key: 'acc_edit', label: 'Edit accounts' },
      { key: 'acc_edit_pass', label: 'Edit passwords' },
      { key: 'acc_add', label: 'Create accounts' },
      { key: 'acc_delete', label: 'Delete accounts' },
      { key: 'acc_files', label: 'Manage files' },
      { key: 'acc_private', label: 'Use private accounts' },
      { key: 'acc_private_group', label: 'Use group-private accounts' },
      { key: 'acc_permission', label: 'Manage ACL' },
      { key: 'acc_public_links', label: 'Manage public links' },
      { key: 'acc_global_search', label: 'Use global search' },
    ],
  },
  {
    title: 'Configuration',
    fields: [
      { key: 'config_general', label: 'General settings' },
      { key: 'config_encryption', label: 'Encryption settings' },
      { key: 'config_backup', label: 'Backup settings' },
      { key: 'config_import', label: 'Import settings' },
    ],
  },
  {
    title: 'Management',
    fields: [
      { key: 'mgm_users', label: 'Manage users' },
      { key: 'mgm_groups', label: 'Manage groups' },
      { key: 'mgm_profiles', label: 'Manage profiles' },
      { key: 'mgm_categories', label: 'Manage categories' },
      { key: 'mgm_customers', label: 'Manage clients' },
      { key: 'mgm_api_tokens', label: 'Manage API tokens' },
      { key: 'mgm_public_links', label: 'Manage public links' },
      { key: 'mgm_accounts', label: 'Manage accounts' },
      { key: 'mgm_tags', label: 'Manage tags' },
      { key: 'mgm_files', label: 'Manage files' },
      { key: 'mgm_items_preset', label: 'Manage item presets' },
      { key: 'mgm_custom_fields', label: 'Manage custom fields' },
      { key: 'evl', label: 'View event log' },
    ],
  },
]

const columns = [
  { name: 'id', label: 'ID', field: 'id', sortable: true, align: 'left' },
  { name: 'name', label: 'Name', field: 'name', sortable: true, align: 'left' },
  { name: 'permissions', label: 'Permissions', field: 'permissions', align: 'left' },
  { name: 'assigned_user_count', label: 'Users', field: 'assigned_user_count', sortable: true, align: 'center' },
  { name: 'actions', label: 'Actions', field: 'actions', align: 'right' },
]

const form = ref(emptyForm())

function emptyPermissions() {
  return permissionSections.flatMap(section => section.fields).reduce((acc, field) => {
    acc[field.key] = false
    return acc
  }, {})
}

function emptyForm() {
  return {
    name: '',
    permissions: emptyPermissions(),
  }
}

function enabledPermissions(permissions) {
  return Object.entries(permissions || {})
    .filter(([, value]) => value)
    .map(([key]) => key)
}

function permissionLabel(key) {
  for (const section of permissionSections) {
    const field = section.fields.find(item => item.key === key)
    if (field) return field.label
  }
  return key
}

async function load() {
  loading.value = true
  try {
    const response = await api.get('/user-profiles')
    profiles.value = response.data
  } catch {
    Notify.create({ message: 'Failed to load user profiles', color: 'negative' })
  } finally {
    loading.value = false
  }
}

function openDialog(item = null) {
  editItem.value = item
  form.value = item
    ? {
        name: item.name,
        permissions: { ...emptyPermissions(), ...(item.permissions || {}) },
      }
    : emptyForm()
  showDialog.value = true
}

async function save() {
  if (!form.value.name) {
    Notify.create({ message: 'Name is required', color: 'warning' })
    return
  }

  saving.value = true
  try {
    if (editItem.value) {
      await api.put(`/user-profiles/${editItem.value.id}`, form.value)
    } else {
      await api.post('/user-profiles', form.value)
    }
    Notify.create({ message: `Profile ${editItem.value ? 'updated' : 'created'}`, color: 'positive' })
    showDialog.value = false
    await load()
  } catch (error) {
    Notify.create({ message: error.response?.data?.detail || 'Failed to save profile', color: 'negative' })
  } finally {
    saving.value = false
  }
}

function confirmDelete(item) {
  Dialog.create({
    title: 'Delete Profile',
    message: `Delete profile "${item.name}"?`,
    cancel: true,
    persistent: true,
  }).onOk(async () => {
    try {
      await api.delete(`/user-profiles/${item.id}`)
      Notify.create({ message: 'Profile deleted', color: 'positive' })
      await load()
    } catch (error) {
      Notify.create({ message: error.response?.data?.detail || 'Failed to delete profile', color: 'negative' })
    }
  })
}

onMounted(load)
</script>
