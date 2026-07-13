<template>
  <q-page class="q-pa-md">
    <div class="row items-center q-mb-lg">
      <div>
        <h4 class="text-h4 text-weight-bold q-ma-none">Plugins</h4>
        <p class="text-body2 text-grey-6 q-ma-none">
          Discover local plugins, manage availability, and configure platform hooks.
        </p>
      </div>
      <q-space />
      <q-btn color="primary" icon="sync" label="Sync Plugins" no-caps :loading="syncing" @click="syncPlugins" />
    </div>

    <q-card flat bordered class="q-mb-lg">
      <q-card-section class="row items-start q-col-gutter-lg">
        <div class="col-12 col-md-7">
          <div class="text-subtitle1 text-weight-medium q-mb-sm">Platform Hooks</div>
          <div class="text-caption text-grey-6 q-mb-md">
            Enabled plugins can implement any of these hook methods in their plugin class.
          </div>
          <q-list dense separator>
            <q-item v-for="hook in hooks" :key="hook.name">
              <q-item-section>
                <q-item-label class="text-weight-medium">{{ hook.name }}</q-item-label>
                <q-item-label caption>{{ hook.description }}</q-item-label>
              </q-item-section>
            </q-item>
          </q-list>
        </div>
        <div class="col-12 col-md-5">
          <div class="text-subtitle1 text-weight-medium q-mb-sm">Plugin Layout</div>
          <div class="text-caption text-grey-6 q-mb-sm">
            Plugins are loaded from the local <code>./plugins</code> directory.
          </div>
          <q-markup-table flat dense class="sp-plugin-layout">
            <tbody>
              <tr><td><code>plugins/&lt;name&gt;/manifest.json</code></td></tr>
              <tr><td><code>plugins/&lt;name&gt;/&lt;name&gt;.py</code></td></tr>
            </tbody>
          </q-markup-table>
        </div>
      </q-card-section>
    </q-card>

    <q-card flat bordered>
      <q-table
        :rows="plugins"
        :columns="columns"
        row-key="name"
        :loading="loading"
        flat dense
        :rows-per-page-options="[25, 50]"
        no-data-label="No plugins discovered yet. Add plugin folders under ./plugins and click Sync Plugins."
      >
        <template v-slot:body-cell-available="props">
          <q-td :props="props">
            <q-badge :color="props.value ? 'positive' : 'grey-6'" :label="props.value ? 'Available' : 'Missing'" />
          </q-td>
        </template>
        <template v-slot:body-cell-enabled="props">
          <q-td :props="props">
            <q-toggle
              :model-value="props.value"
              color="primary"
              :disable="!props.row.available || toggling === props.row.name"
              @update:model-value="val => togglePlugin(props.row, val)"
            />
          </q-td>
        </template>
        <template v-slot:body-cell-hooks="props">
          <q-td :props="props">
            <div class="row q-gutter-xs">
              <q-badge v-for="hook in props.value" :key="hook" color="blue-grey-1" text-color="blue-grey-9" :label="hook" />
              <span v-if="!props.value?.length" class="text-grey-5">—</span>
            </div>
          </q-td>
        </template>
        <template v-slot:body-cell-actions="props">
          <q-td :props="props" auto-width>
            <q-btn flat dense round icon="settings" color="primary" size="sm" @click="openConfig(props.row)" />
          </q-td>
        </template>
      </q-table>
    </q-card>

    <q-dialog v-model="dialog" persistent>
      <q-card style="min-width: 640px; max-width: 90vw">
        <q-card-section class="row items-center q-pb-none">
          <div class="text-h6">Configure {{ selected?.name }}</div>
          <q-space />
          <q-btn icon="close" flat round dense v-close-popup />
        </q-card-section>
        <q-card-section class="q-gutter-md">
          <div class="text-caption text-grey-6">
            {{ selected?.description || 'No description provided.' }}
          </div>
          <q-banner v-if="selected?.config_schema && Object.keys(selected.config_schema).length" dense rounded class="bg-blue-1 text-blue-9">
            This plugin exposes a config schema.
            <code class="block q-mt-sm">{{ JSON.stringify(selected.config_schema, null, 2) }}</code>
          </q-banner>
          <q-input
            v-model="configText"
            type="textarea"
            outlined dense autogrow
            label="Plugin config (JSON)"
            :error="!!jsonError"
            :error-message="jsonError"
            @update:model-value="validateJson"
          />
        </q-card-section>
        <q-card-actions align="right">
          <q-btn flat label="Cancel" no-caps v-close-popup />
          <q-btn unelevated color="primary" label="Save Config" no-caps :loading="saving" @click="saveConfig" />
        </q-card-actions>
      </q-card>
    </q-dialog>
  </q-page>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Notify } from 'quasar'
import api from '@/api/axios'

const plugins = ref([])
const hooks = ref([])
const loading = ref(false)
const syncing = ref(false)
const toggling = ref('')
const dialog = ref(false)
const selected = ref(null)
const configText = ref('{}')
const jsonError = ref('')
const saving = ref(false)

const columns = [
  { name: 'name', label: 'Plugin', field: 'name', align: 'left', sortable: true },
  { name: 'version', label: 'Version', field: 'version', align: 'left', sortable: true },
  { name: 'author', label: 'Author', field: 'author', align: 'left' },
  { name: 'available', label: 'Availability', field: 'available', align: 'center' },
  { name: 'enabled', label: 'Enabled', field: 'enabled', align: 'center' },
  { name: 'hooks', label: 'Hooks', field: 'hooks', align: 'left' },
  { name: 'actions', label: '', field: 'actions', align: 'right' },
]

function validateJson(val) {
  try {
    JSON.parse(val)
    jsonError.value = ''
  } catch {
    jsonError.value = 'Invalid JSON'
  }
}

async function load() {
  loading.value = true
  try {
    const [pluginsRes, hooksRes] = await Promise.all([
      api.get('/plugins'),
      api.get('/plugins/hooks'),
    ])
    plugins.value = pluginsRes.data
    hooks.value = hooksRes.data
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Failed to load plugins', color: 'negative' })
  } finally {
    loading.value = false
  }
}

async function syncPlugins() {
  syncing.value = true
  try {
    const r = await api.post('/plugins/sync')
    plugins.value = r.data
    Notify.create({ message: 'Plugin registry synced', color: 'positive' })
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Sync failed', color: 'negative' })
  } finally {
    syncing.value = false
  }
}

async function togglePlugin(row, enabled) {
  toggling.value = row.name
  try {
    await api.post(`/plugins/${encodeURIComponent(row.name)}/${enabled ? 'enable' : 'disable'}`)
    await load()
    Notify.create({ message: `${row.name} ${enabled ? 'enabled' : 'disabled'}`, color: 'positive' })
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Plugin update failed', color: 'negative' })
  } finally {
    toggling.value = ''
  }
}

async function openConfig(row) {
  try {
    const r = await api.get(`/plugins/${encodeURIComponent(row.name)}`)
    selected.value = r.data
    configText.value = JSON.stringify(r.data.config || {}, null, 2)
    jsonError.value = ''
    dialog.value = true
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Failed to load plugin details', color: 'negative' })
  }
}

async function saveConfig() {
  if (jsonError.value) return
  let parsed
  try {
    parsed = JSON.parse(configText.value)
  } catch {
    return
  }
  saving.value = true
  try {
    const r = await api.put(`/plugins/${encodeURIComponent(selected.value.name)}/config`, { config: parsed })
    selected.value = r.data
    dialog.value = false
    await load()
    Notify.create({ message: 'Plugin config updated', color: 'positive' })
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Save failed', color: 'negative' })
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.sp-plugin-layout td {
  white-space: normal;
}
</style>
