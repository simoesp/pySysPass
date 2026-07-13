<template>
  <q-page class="q-pa-md">
    <div class="row justify-between items-center q-mb-lg">
      <div>
        <h4 class="text-h4 text-weight-bold q-ma-none">User Groups</h4>
        <p class="text-body2 text-grey-6">Manage groups and their members</p>
      </div>
      <q-btn color="primary" icon="add" label="New Group" @click="openDialog()" />
    </div>

    <q-table
      :rows="groups"
      :columns="columns"
      row-key="id"
      :loading="loading"
      flat
      bordered
    >
      <template v-slot:body-cell-actions="props">
        <q-td :props="props" class="q-gutter-xs">
          <q-btn flat dense icon="group" color="info" label="Members" @click="openMembers(props.row)" />
          <q-btn flat dense icon="edit" color="primary" @click="openDialog(props.row)" />
          <q-btn flat dense icon="delete" color="negative" @click="confirmDelete(props.row)" />
        </q-td>
      </template>
    </q-table>

    <!-- Create / Edit dialog -->
    <q-dialog v-model="showDialog">
      <q-card style="min-width: 420px">
        <q-card-section>
          <div class="text-h6">{{ editItem ? 'Edit Group' : 'New Group' }}</div>
        </q-card-section>
        <q-card-section class="q-pt-none q-gutter-md">
          <q-input v-model="form.name" label="Name *" outlined dense />
          <q-input v-model="form.description" label="Description" outlined dense />
          <CustomFieldsPanel v-if="showDialog" ref="cfPanel" :module-id="801" :item-id="editItem?.id ?? null" />
        </q-card-section>
        <q-card-actions align="right">
          <q-btn flat label="Cancel" v-close-popup />
          <q-btn color="primary" :label="editItem ? 'Save' : 'Create'" :loading="saving" @click="save" />
        </q-card-actions>
      </q-card>
    </q-dialog>

    <!-- Members dialog -->
    <q-dialog v-model="showMembers">
      <q-card style="min-width: 480px">
        <q-card-section class="row items-center">
          <div class="text-h6">Members of {{ selectedGroup?.name }}</div>
          <q-space />
          <q-btn flat round icon="close" v-close-popup />
        </q-card-section>
        <q-card-section>
          <q-list bordered separator>
            <q-item v-for="m in members" :key="m.user_id">
              <q-item-section avatar>
                <q-avatar color="primary" text-color="white" size="sm">
                  {{ m.username?.charAt(0).toUpperCase() }}
                </q-avatar>
              </q-item-section>
              <q-item-section>
                <q-item-label>{{ m.username }}</q-item-label>
                <q-item-label caption>{{ m.email }}</q-item-label>
              </q-item-section>
              <q-item-section side>
                <q-btn flat dense icon="remove_circle" color="negative"
                  @click="removeMember(m.user_id)" />
              </q-item-section>
            </q-item>
            <q-item v-if="members.length === 0">
              <q-item-section class="text-grey-6">No members yet</q-item-section>
            </q-item>
          </q-list>
        </q-card-section>
      </q-card>
    </q-dialog>
  </q-page>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Notify, Dialog } from 'quasar'
import api from '@/api/axios'
import CustomFieldsPanel from '@/components/CustomFieldsPanel.vue'

const groups = ref([])
const members = ref([])
const loading = ref(false)
const saving = ref(false)
const showDialog = ref(false)
const showMembers = ref(false)
const editItem = ref(null)
const selectedGroup = ref(null)
const cfPanel = ref(null)
const form = ref({ name: '', description: '' })

const columns = [
  { name: 'id', label: 'ID', field: 'id', sortable: true, align: 'left' },
  { name: 'name', label: 'Name', field: 'name', sortable: true, align: 'left' },
  { name: 'description', label: 'Description', field: 'description', align: 'left' },
  { name: 'actions', label: 'Actions', field: 'actions', align: 'right' }
]

async function load() {
  loading.value = true
  try {
    const r = await api.get('/user-groups')
    groups.value = r.data
  } catch {
    Notify.create({ message: 'Failed to load groups', color: 'negative' })
  } finally {
    loading.value = false
  }
}

function openDialog(item = null) {
  editItem.value = item
  form.value = item ? { name: item.name, description: item.description || '' } : { name: '', description: '' }
  showDialog.value = true
}

async function save() {
  if (!form.value.name) return Notify.create({ message: 'Name is required', color: 'warning' })
  saving.value = true
  try {
    let itemId
    if (editItem.value) {
      await api.put(`/user-groups/${editItem.value.id}`, form.value)
      itemId = editItem.value.id
    } else {
      const r = await api.post('/user-groups', form.value)
      itemId = r.data.id
    }
    await cfPanel.value?.save(itemId)
    Notify.create({ message: `Group ${editItem.value ? 'updated' : 'created'}`, color: 'positive' })
    showDialog.value = false
    await load()
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Failed to save', color: 'negative' })
  } finally {
    saving.value = false
  }
}

async function openMembers(group) {
  selectedGroup.value = group
  try {
    const r = await api.get(`/user-groups/${group.id}/members`)
    members.value = r.data
  } catch {
    members.value = []
  }
  showMembers.value = true
}

async function removeMember(userId) {
  try {
    await api.delete(`/user-groups/${selectedGroup.value.id}/members/${userId}`)
    members.value = members.value.filter(m => m.user_id !== userId)
    Notify.create({ message: 'Member removed', color: 'positive' })
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Failed to remove member', color: 'negative' })
  }
}

function confirmDelete(item) {
  Dialog.create({
    title: 'Delete Group',
    message: `Delete group "${item.name}"?`,
    cancel: true,
    persistent: true
  }).onOk(async () => {
    try {
      await api.delete(`/user-groups/${item.id}`)
      Notify.create({ message: 'Group deleted', color: 'positive' })
      await load()
    } catch (e) {
      Notify.create({ message: e.response?.data?.detail || 'Failed to delete', color: 'negative' })
    }
  })
}

onMounted(load)
</script>
