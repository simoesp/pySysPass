<template>
  <q-page class="sp-accounts-page">
    <!-- ── Toolbar ── -->
    <div class="sp-page-header">
      <div>
        <div class="text-h5 text-weight-bold text-grey-9">Accounts</div>
        <div class="text-caption text-grey-6">{{ rangeLabel }}</div>
      </div>
      <div class="row q-gutter-sm items-center">
        <q-input v-model="search" outlined dense placeholder="Search…" bg-color="white"
          style="width: 240px" clearable>
          <template v-slot:prepend><q-icon name="search" color="grey-5" /></template>
        </q-input>
        <q-btn unelevated color="primary" icon="add" label="New account" no-caps @click="openAdd" />
      </div>
    </div>

    <!-- ── Filter bar ── -->
    <div class="sp-filter-bar" v-if="clients.length || categories.length || allTags.length">

      <q-select v-if="clients.length"
        v-model="selectedClient"
        :options="clients"
        option-label="name"
        option-value="id"
        emit-value map-options
        clearable
        dense outlined
        placeholder="Client"
        bg-color="white"
        style="min-width: 160px">
        <template v-slot:prepend><q-icon name="business" size="16px" color="grey-6" /></template>
      </q-select>

      <q-select v-if="categories.length"
        v-model="selectedCategory"
        :options="categories"
        option-label="name"
        option-value="id"
        emit-value map-options
        clearable
        dense outlined
        placeholder="Category"
        bg-color="white"
        style="min-width: 160px">
        <template v-slot:prepend><q-icon name="folder_open" size="16px" color="grey-6" /></template>
      </q-select>

      <q-select v-if="allTags.length"
        v-model="selectedTag"
        :options="allTags"
        option-label="name"
        option-value="id"
        emit-value map-options
        clearable
        dense outlined
        placeholder="Tag"
        bg-color="white"
        style="min-width: 140px">
        <template v-slot:prepend><q-icon name="label_outline" size="16px" color="grey-6" /></template>
        <template v-slot:option="scope">
          <q-item v-bind="scope.itemProps">
            <q-item-section avatar>
              <span class="sp-tag-dot" :style="{ background: scope.opt.color || '#888' }" />
            </q-item-section>
            <q-item-section>{{ scope.opt.name }}</q-item-section>
          </q-item>
        </template>
      </q-select>

    </div>

    <!-- ── Loading ── -->
    <div v-if="loading" class="sp-empty-state">
      <q-spinner-dots size="48px" color="primary" />
      <div class="text-grey-5 q-mt-md">Loading accounts…</div>
    </div>

    <!-- ── Empty ── -->
    <div v-else-if="accounts.length === 0" class="sp-empty-state">
      <q-icon name="lock_open" size="64px" color="grey-3" />
      <div class="text-h6 text-grey-5 q-mt-md">No accounts found</div>
      <div class="text-body2 text-grey-4 q-mb-lg">
        {{ search || activeFilterCount ? 'Try adjusting your search or filters' : 'Create your first account to get started' }}
      </div>
      <q-btn v-if="!search && !activeFilterCount"
        unelevated color="primary" icon="add" label="New account" no-caps @click="openAdd" />
    </div>

    <!-- ── Grid ── -->
    <div v-else class="sp-grid">
      <div v-for="acc in accounts" :key="acc.id" class="sp-card"
        @click="$router.push(`/accounts/${acc.id}`)">

        <!-- Favicon -->
        <div class="sp-card-icon">
          <img v-if="faviconUrl(acc.url)" :src="faviconUrl(acc.url)" :alt="acc.title"
            @error="e => e.target.style.display='none'" />
          <q-icon v-else name="language" color="grey-4" size="28px" />
        </div>

        <!-- Main content -->
        <div class="sp-card-body">
          <div class="sp-card-title">{{ acc.title }}</div>
          <div class="sp-card-login text-grey-6" v-if="acc.login">
            <q-icon name="person_outline" size="13px" class="q-mr-xs" />{{ acc.login }}
          </div>
          <div class="sp-card-url text-grey-5" v-if="acc.url">
            <q-icon name="link" size="13px" class="q-mr-xs" />{{ displayUrl(acc.url) }}
          </div>
        </div>

        <!-- Badges -->
        <div class="sp-card-meta">
          <q-badge v-if="categoryName(acc.category_id)" color="blue-1" text-color="primary" class="sp-badge">
            {{ categoryName(acc.category_id) }}
          </q-badge>
          <q-badge v-if="clientName(acc.client_id)" color="teal-1" text-color="teal-8" class="sp-badge">
            <q-icon name="business" size="11px" class="q-mr-xs" />{{ clientName(acc.client_id) }}
          </q-badge>
          <q-badge v-if="!acc.is_public" color="grey-3" text-color="grey-8" class="sp-badge">
            Private
          </q-badge>
          <q-badge v-if="acc.is_private_group" color="indigo-1" text-color="indigo-8" class="sp-badge">
            Group-private
          </q-badge>
          <q-badge v-if="(acc.shared_users?.length || 0) + (acc.shared_groups?.length || 0)" color="teal-1" text-color="teal-8" class="sp-badge">
            Shared {{ (acc.shared_users?.length || 0) + (acc.shared_groups?.length || 0) }}
          </q-badge>
          <q-badge v-if="acc.is_favorite" color="amber-1" text-color="amber-9" class="sp-badge">
            <q-icon name="star" size="11px" class="q-mr-xs" />Favourite
          </q-badge>
          <!-- Password expiry warning -->
          <q-badge v-if="isExpiringSoon(acc)" color="red-1" text-color="negative" class="sp-badge">
            <q-icon name="schedule" size="11px" class="q-mr-xs" />Pwd expiring
          </q-badge>
          <!-- Tags -->
          <template v-if="acc.tags && acc.tags.length">
            <span v-for="tag in acc.tags.slice(0, 3)" :key="tag.id"
              class="sp-tag-dot"
              :style="{ background: tag.color || '#888' }"
              :title="tag.name" />
            <span v-if="acc.tags.length > 3" class="text-caption text-grey-5">+{{ acc.tags.length - 3 }}</span>
          </template>
        </div>

        <!-- Actions -->
        <div class="sp-card-actions" @click.stop>
          <q-btn flat round dense
            :icon="acc.is_favorite ? 'star' : 'star_outline'"
            :color="acc.is_favorite ? 'amber-8' : 'grey-5'"
            size="sm"
            @click.stop="toggleFav(acc)">
            <q-tooltip>{{ acc.is_favorite ? 'Remove favourite' : 'Add favourite' }}</q-tooltip>
          </q-btn>
          <q-btn flat round dense
            :icon="copyStates[acc.id] ? 'check' : 'content_copy'"
            :color="copyStates[acc.id] ? 'positive' : 'grey-5'"
            size="sm" @click.stop="copyPassword(acc.id)">
            <q-tooltip>Copy password</q-tooltip>
          </q-btn>
          <q-btn flat round dense icon="open_in_new" color="grey-5" size="sm"
            v-if="acc.url" @click.stop="openUrl(acc.url)">
            <q-tooltip>Open URL</q-tooltip>
          </q-btn>
          <q-btn flat round dense icon="more_vert" color="grey-5" size="sm">
            <q-tooltip>More</q-tooltip>
            <q-menu anchor="bottom right" self="top right">
              <q-list dense style="min-width: 160px">
                <q-item clickable v-ripple @click="$router.push(`/accounts/${acc.id}`)" v-close-popup>
                  <q-item-section avatar><q-icon name="edit" size="sm" /></q-item-section>
                  <q-item-section>Edit</q-item-section>
                </q-item>
                <q-item clickable v-ripple @click="cloneAccount(acc)" v-close-popup>
                  <q-item-section avatar><q-icon name="content_copy" size="sm" /></q-item-section>
                  <q-item-section>Clone</q-item-section>
                </q-item>
                <q-separator />
                <q-item v-if="acc.is_owner" clickable v-ripple @click="confirmDelete(acc)" v-close-popup class="text-negative">
                  <q-item-section avatar><q-icon name="delete_outline" size="sm" color="negative" /></q-item-section>
                  <q-item-section>Delete</q-item-section>
                </q-item>
              </q-list>
            </q-menu>
          </q-btn>
        </div>
      </div>
    </div>

    <!-- ── Pagination ── -->
    <div v-if="!loading && total > pageSize" class="sp-pagination row items-center justify-center q-gutter-md q-py-md">
      <q-pagination
        v-model="page"
        :max="pagesCount"
        :max-pages="7"
        boundary-numbers
        direction-links
        color="primary"
        active-design="unelevated" />
      <q-select
        v-model="pageSize"
        :options="[12, 24, 48, 96]"
        dense outlined
        bg-color="white"
        style="width: 90px"
        label="Per page" />
    </div>

    <!-- ── Add dialog ── -->
    <q-dialog v-model="showAdd" persistent>
      <q-card style="min-width: 540px; max-width: 95vw">
        <q-card-section class="row items-center q-pb-none">
          <div class="text-h6">New account</div>
          <q-space /><q-btn flat round dense icon="close" v-close-popup />
        </q-card-section>

        <q-card-section class="q-pt-md q-gutter-y-sm">
          <q-input v-model="form.title" label="Name *" outlined dense />
          <div class="row q-gutter-sm">
            <q-input v-model="form.login" label="Username / Login" outlined dense class="col" />
            <q-input v-model="form.password" :type="showNewPwd ? 'text' : 'password'"
              label="Password *" outlined dense class="col">
              <template v-slot:append>
                <PasswordGenerator @use="form.password = $event; showNewPwd = true" />
                <q-icon :name="showNewPwd ? 'visibility_off' : 'visibility'"
                  class="cursor-pointer" color="grey-5" @click="showNewPwd = !showNewPwd" />
              </template>
            </q-input>
          </div>
          <q-input v-model="form.url" label="URL" outlined dense />
          <div class="row q-gutter-sm">
            <q-select v-model="form.category_id" :options="catOpts" option-label="name"
              option-value="id" label="Category" outlined dense emit-value map-options class="col" clearable
              use-input hide-selected fill-input input-debounce="0" @filter="filterCats" />
            <q-select v-model="form.client_id" :options="clientOpts" option-label="name"
              option-value="id" label="Client" outlined dense emit-value map-options class="col" clearable
              use-input hide-selected fill-input input-debounce="0" @filter="filterClients" />
          </div>
          <!-- Tags -->
          <q-select v-model="form.tag_ids" :options="tagOpts" option-label="name" option-value="id"
            label="Tags" outlined dense emit-value map-options multiple use-chips clearable
            use-input fill-input input-debounce="0" @filter="filterTags">
            <template v-slot:selected-item="scope">
              <q-chip removable dense
                :style="{ background: tagColor(scope.opt) + '33', color: tagColor(scope.opt) }"
                @remove="scope.removeAtIndex(scope.index)">
                {{ scope.opt.name || tagName(scope.opt) }}
              </q-chip>
            </template>
          </q-select>
          <q-input v-model="form.notes" label="Notes" outlined dense type="textarea" rows="3" />
          <q-toggle v-model="form.is_public" label="Public (visible to all users)" />
          <q-toggle v-model="form.is_private_group" label="Private to owning group" />
          <q-toggle v-model="form.other_user_edit" label="Allow direct shared users to edit" />
          <q-toggle v-model="form.other_user_group_edit" label="Allow shared groups to edit" />
          <q-input v-model="form.pass_date_change_date" label="Password change date" outlined dense type="date" />

          <q-select
            :model-value="form.shared_users.map(entry => entry.user_id)"
            :options="userOptions"
            option-label="username"
            option-value="id"
            label="Shared users"
            outlined
            dense
            emit-value
            map-options
            multiple
            use-chips
            clearable
            @update:model-value="updateSharedUsers"
          />
          <div v-if="form.shared_users.length" class="q-gutter-sm">
            <div v-for="entry in form.shared_users" :key="`user-${entry.user_id}`" class="row items-center justify-between bg-grey-1 rounded-borders q-px-sm q-py-xs">
              <div class="text-body2">{{ userLabel(entry.user_id) }}</div>
              <q-toggle v-model="entry.is_edit" dense label="Can edit" />
            </div>
          </div>

          <q-select
            :model-value="form.shared_groups.map(entry => entry.group_id)"
            :options="groupOptions"
            option-label="name"
            option-value="id"
            label="Shared groups"
            outlined
            dense
            emit-value
            map-options
            multiple
            use-chips
            clearable
            @update:model-value="updateSharedGroups"
          />
          <div v-if="form.shared_groups.length" class="q-gutter-sm">
            <div v-for="entry in form.shared_groups" :key="`group-${entry.group_id}`" class="row items-center justify-between bg-grey-1 rounded-borders q-px-sm q-py-xs">
              <div class="text-body2">{{ groupLabel(entry.group_id) }}</div>
              <q-toggle v-model="entry.is_edit" dense label="Can edit" />
            </div>
          </div>
        </q-card-section>

        <q-card-actions align="right" class="q-pa-md">
          <q-btn flat label="Cancel" v-close-popup />
          <q-btn unelevated color="primary" label="Create" :loading="saving" no-caps @click="createAccount" />
        </q-card-actions>
      </q-card>
    </q-dialog>
  </q-page>
</template>

<script setup>
import { ref, computed, onMounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import { Notify, Dialog } from 'quasar'
import api from '@/api/axios'
import { encryptPassword } from '@/composables/useClientEncryption'
import PasswordGenerator from '@/components/PasswordGenerator.vue'

const router = useRouter()

const accounts = ref([])
const categories = ref([])
const clients = ref([])
const allTags = ref([])
const users = ref([])
const groups = ref([])
const catOpts = ref([])
const clientOpts = ref([])
const tagOpts = ref([])
const userOptions = ref([])
const groupOptions = ref([])
const search = ref('')
const selectedCategory = ref(null)
const selectedClient = ref(null)
const selectedTag = ref(null)
const loading = ref(false)
const total = ref(0)
const page = ref(1)
const pageSize = ref(24)
const saving = ref(false)
const showAdd = ref(false)
const showNewPwd = ref(false)
const copyStates = ref({})

const form = ref({
  title: '', login: '', password: '', url: '',
  category_id: null, client_id: null, notes: '', is_public: false, tag_ids: [],
  is_private_group: false, other_user_edit: false, other_user_group_edit: false,
  pass_date_change_date: '', shared_users: [], shared_groups: [],
})

// ── Computed ──────────────────────────────────────────────────────────────
const activeFilterCount = computed(() =>
  (selectedClient.value !== null ? 1 : 0) +
  (selectedCategory.value !== null ? 1 : 0) +
  (selectedTag.value !== null ? 1 : 0)
)

const tagChipColor = computed(() => {
  const tag = allTags.value.find(t => t.id === selectedTag.value)
  return tag?.color || '#888'
})

const tagChipLabel = computed(() => {
  return allTags.value.find(t => t.id === selectedTag.value)?.name || ''
})

function clearFilters() {
  selectedClient.value = null
  selectedCategory.value = null
  selectedTag.value = null
}

const pagesCount = computed(() => Math.max(1, Math.ceil(total.value / pageSize.value)))

const rangeLabel = computed(() => {
  if (total.value === 0) return '0 entries'
  const first = (page.value - 1) * pageSize.value + 1
  const last = Math.min(page.value * pageSize.value, total.value)
  return `${first}–${last} of ${total.value} entries`
})

// ── Filter functions ──────────────────────────────────────────────────────
function filterCats(val, update) {
  update(() => {
    catOpts.value = val
      ? categories.value.filter(o => o.name.toLowerCase().includes(val.toLowerCase()))
      : [...categories.value]
  })
}
function filterClients(val, update) {
  update(() => {
    clientOpts.value = val
      ? clients.value.filter(o => o.name.toLowerCase().includes(val.toLowerCase()))
      : [...clients.value]
  })
}
function filterTags(val, update) {
  update(() => {
    tagOpts.value = val
      ? allTags.value.filter(o => o.name.toLowerCase().includes(val.toLowerCase()))
      : [...allTags.value]
  })
}

// ── Helpers ───────────────────────────────────────────────────────────────
function faviconUrl(url) {
  if (!url) return null
  try {
    const host = new URL(url.startsWith('http') ? url : `https://${url}`).hostname
    return `https://icons.duckduckgo.com/ip3/${host}.ico`
  } catch { return null }
}
function displayUrl(url) {
  try { return new URL(url.startsWith('http') ? url : `https://${url}`).hostname } catch { return url }
}
function categoryName(id) {
  return categories.value.find(c => c.id === id)?.name || null
}
function clientName(id) {
  return clients.value.find(c => c.id === id)?.name || null
}
function openUrl(url) {
  window.open(url.startsWith('http') ? url : `https://${url}`, '_blank', 'noopener')
}
function isExpiringSoon(acc) {
  if (!acc.pass_date_change) return false
  const daysLeft = (acc.pass_date_change * 1000 - Date.now()) / 86400000
  return daysLeft >= 0 && daysLeft <= 30
}
function tagColor(opt) {
  if (typeof opt === 'object' && opt?.color) return opt.color
  const tag = allTags.value.find(t => t.id === opt)
  return tag?.color || '#888'
}
function tagName(opt) {
  if (typeof opt === 'object') return opt.name
  return allTags.value.find(t => t.id === opt)?.name || ''
}
function userLabel(id) {
  return users.value.find(u => u.id === id)?.username || `User ${id}`
}
function groupLabel(id) {
  return groups.value.find(g => g.id === id)?.name || `Group ${id}`
}
function toDateInput(ts) {
  if (!ts) return ''
  return new Date(ts * 1000).toISOString().slice(0, 10)
}
function toUnixTimestamp(dateValue) {
  if (!dateValue) return null
  return Math.floor(new Date(`${dateValue}T00:00:00Z`).getTime() / 1000)
}
function normalizeSharedUsers(value) {
  return (value || []).map(entry =>
    typeof entry === 'number'
      ? { user_id: entry, is_edit: false }
      : { user_id: entry.user_id, is_edit: !!entry.is_edit }
  )
}
function normalizeSharedGroups(value) {
  return (value || []).map(entry =>
    typeof entry === 'number'
      ? { group_id: entry, is_edit: false }
      : { group_id: entry.group_id, is_edit: !!entry.is_edit }
  )
}
function updateSharedUsers(ids) {
  const current = new Map((form.value.shared_users || []).map(entry => [entry.user_id, !!entry.is_edit]))
  form.value.shared_users = (ids || []).map(userId => ({
    user_id: userId,
    is_edit: current.get(userId) || false,
  }))
}
function updateSharedGroups(ids) {
  const current = new Map((form.value.shared_groups || []).map(entry => [entry.group_id, !!entry.is_edit]))
  form.value.shared_groups = (ids || []).map(groupId => ({
    group_id: groupId,
    is_edit: current.get(groupId) || false,
  }))
}

// ── Actions ───────────────────────────────────────────────────────────────
async function copyPassword(id) {
  try {
    const r = await api.get(`/accounts/${id}/password`)
    await navigator.clipboard.writeText(r.data.password)
    copyStates.value = { ...copyStates.value, [id]: true }
    setTimeout(() => { copyStates.value = { ...copyStates.value, [id]: false } }, 2000)
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Failed to copy', color: 'negative' })
  }
}

async function toggleFav(acc) {
  try {
    const r = await api.post(`/accounts/${acc.id}/favorite`)
    acc.is_favorite = r.data.is_favorite
  } catch (e) {
    Notify.create({ message: 'Failed to update favourite', color: 'negative' })
  }
}

async function cloneAccount(acc) {
  try {
    const r = await api.post(`/accounts/${acc.id}/copy`)
    Notify.create({ message: `Cloned as "${r.data.title}"`, color: 'positive' })
    router.push(`/accounts/${r.data.id}`)
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Failed to clone', color: 'negative' })
  }
}

function openAdd() {
  form.value = {
    title: '', login: '', password: '', url: '', category_id: null, client_id: null, notes: '',
    is_public: false, tag_ids: [], is_private_group: false, other_user_edit: false,
    other_user_group_edit: false, pass_date_change_date: '', shared_users: [], shared_groups: [],
  }
  showNewPwd.value = false
  showAdd.value = true
}

async function createAccount() {
  if (!form.value.title || !form.value.password) {
    Notify.create({ message: 'Name and password are required', color: 'warning' })
    return
  }
  saving.value = true
  try {
    const payload = {
      ...form.value,
      password: await encryptPassword(form.value.password),
      pass_date_change: toUnixTimestamp(form.value.pass_date_change_date),
      shared_users: normalizeSharedUsers(form.value.shared_users),
      shared_groups: normalizeSharedGroups(form.value.shared_groups),
    }
    delete payload.pass_date_change_date
    await api.post('/accounts', payload)
    Notify.create({ message: 'Account created', color: 'positive' })
    showAdd.value = false
    await loadAccounts()
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Failed to create', color: 'negative' })
  } finally {
    saving.value = false
  }
}

function confirmDelete(acc) {
  Dialog.create({
    title: 'Delete account',
    message: `Delete "${acc.title}"? This cannot be undone.`,
    cancel: { flat: true },
    ok: { label: 'Delete', color: 'negative', unelevated: true },
    persistent: true,
  }).onOk(async () => {
    try {
      await api.delete(`/accounts/${acc.id}`)
      Notify.create({ message: 'Account deleted', color: 'positive' })
      await loadAccounts()
    } catch (e) {
      Notify.create({ message: e.response?.data?.detail || 'Failed to delete', color: 'negative' })
    }
  })
}

// ── Data loading ──────────────────────────────────────────────────────────
function listParams() {
  return {
    ...(search.value ? { q: search.value } : {}),
    ...(selectedCategory.value !== null ? { category_id: selectedCategory.value } : {}),
    ...(selectedClient.value !== null ? { client_id: selectedClient.value } : {}),
    ...(selectedTag.value !== null ? { tag_id: selectedTag.value } : {}),
  }
}

async function loadAccounts() {
  loading.value = true
  try {
    const filters = listParams()
    const params = {
      skip: (page.value - 1) * pageSize.value,
      limit: pageSize.value,
      ...filters,
    }
    const [listRes, countRes] = await Promise.all([
      api.get('/accounts', { params }),
      api.get('/accounts/count', { params: filters }),
    ])
    accounts.value = listRes.data
    total.value = countRes.data?.count ?? 0
    // If deletes/filters shrank the result set below the current page, snap back
    if (page.value > 1 && accounts.value.length === 0 && total.value > 0) {
      page.value = pagesCount.value
    }
  } catch {
    Notify.create({ message: 'Failed to load accounts', color: 'negative' })
  } finally {
    loading.value = false
  }
}

// Filters and page-size changes restart from page 1; search is debounced.
// Resetting the page triggers the page watcher, which reloads.
function reloadFromFirstPage() {
  if (page.value !== 1) page.value = 1
  else loadAccounts()
}

let searchTimer = null
watch(search, () => {
  clearTimeout(searchTimer)
  searchTimer = setTimeout(reloadFromFirstPage, 300)
})
watch([selectedCategory, selectedClient, selectedTag, pageSize], reloadFromFirstPage)
watch(page, loadAccounts)

onMounted(async () => {
  loadAccounts()
  try {
    categories.value = (await api.get('/categories')).data
    catOpts.value = [...categories.value]
  } catch {}
  try {
    users.value = (await api.get('/users')).data
    userOptions.value = [...users.value]
  } catch {}
  try {
    groups.value = (await api.get('/user-groups')).data
    groupOptions.value = [...groups.value]
  } catch {}
  try {
    clients.value = (await api.get('/clients')).data
    clientOpts.value = [...clients.value]
  } catch {}
  try {
    const r = await api.get('/tags')
    allTags.value = r.data
    tagOpts.value = [...r.data]
  } catch {}
})
</script>

<style lang="scss" scoped>
.sp-accounts-page {
  background: var(--sp-content-bg, #f4f6fb);
  min-height: 100vh;
}

.sp-page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 24px 24px 0;
  flex-wrap: wrap;
  gap: 12px;
}

.sp-filter-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
  padding: 14px 24px 4px;
}

.sp-filter-group {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  align-items: center;
}

.sp-empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 80px 24px;
}

.sp-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 14px;
  padding: 20px 24px 32px;
}

.sp-card {
  background: var(--sp-card-bg, #fff);
  border-radius: 12px;
  box-shadow: 0 1px 4px rgba(0,0,0,.07);
  padding: 16px;
  cursor: pointer;
  display: flex;
  flex-direction: column;
  gap: 10px;
  transition: box-shadow .18s, transform .18s;
  border: 1px solid rgba(0,0,0,.04);

  &:hover {
    box-shadow: 0 4px 16px rgba(0,0,0,.12);
    transform: translateY(-2px);
  }
}

.sp-card-icon {
  width: 40px;
  height: 40px;
  border-radius: 10px;
  background: #f0f2f8;
  display: flex;
  align-items: center;
  justify-content: center;
  overflow: hidden;
  flex-shrink: 0;

  img { width: 28px; height: 28px; object-fit: contain; }
}

.sp-card-body { flex: 1; min-width: 0; }

.sp-card-title {
  font-size: 15px;
  font-weight: 600;
  color: var(--sp-text-primary, #111827);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.sp-card-login,
.sp-card-url {
  font-size: 12px;
  margin-top: 3px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  display: flex;
  align-items: center;
}

.sp-card-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  align-items: center;
}

.sp-badge {
  font-size: 11px;
  font-weight: 600;
  border-radius: 4px;
  padding: 2px 6px;
}

.sp-tag-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  display: inline-block;
  flex-shrink: 0;
}

.sp-card-actions {
  display: flex;
  gap: 2px;
  justify-content: flex-end;
  margin-top: -4px;
}
</style>
