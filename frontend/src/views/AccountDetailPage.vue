<template>
  <q-page class="sp-detail-page">
    <!-- ── Back bar ── -->
    <div class="sp-back-bar">
      <q-btn flat dense no-caps icon="arrow_back" label="Accounts" color="grey-7"
        @click="$router.push('/accounts')" />
    </div>

    <!-- ── Loading ── -->
    <div v-if="loading" class="sp-center-state">
      <q-spinner-dots size="48px" color="primary" />
    </div>

    <!-- ── Not found ── -->
    <div v-else-if="!account" class="sp-center-state">
      <q-icon name="error_outline" size="56px" color="grey-4" />
      <div class="text-h6 text-grey-5 q-mt-md">Account not found</div>
      <q-btn flat color="primary" label="Go back" @click="$router.push('/accounts')" class="q-mt-md" />
    </div>

    <!-- ── Detail ── -->
    <div v-else class="sp-detail-wrap">
      <!-- Header card -->
      <div class="sp-detail-header">
        <div class="sp-detail-favicon">
          <img v-if="faviconUrl" :src="faviconUrl" :alt="account.title"
            @error="e => e.target.style.display='none'" />
          <q-icon v-else name="language" size="32px" color="grey-4" />
        </div>
        <div style="flex: 1; min-width: 0">
          <div class="text-h5 text-weight-bold" style="color: var(--sp-text-primary, #111827)">
            {{ account.title }}
          </div>
          <div class="row items-center q-gutter-sm q-mt-xs flex-wrap">
            <div class="text-body2 text-grey-5" v-if="categoryLabel">
              <q-icon name="folder_open" size="14px" class="q-mr-xs" />{{ categoryLabel }}
            </div>
            <q-badge v-if="account.is_public" color="blue-1" text-color="primary">Public</q-badge>
            <q-badge v-else color="grey-3" text-color="grey-8">Private</q-badge>
            <q-badge v-if="account.is_private_group" color="indigo-1" text-color="indigo-8">Group-private</q-badge>
            <q-badge v-if="account.can_edit" color="green-1" text-color="positive">Editable</q-badge>
            <q-badge v-if="isExpiringSoon" color="red-1" text-color="negative">
              <q-icon name="schedule" size="11px" class="q-mr-xs" />Password expiring
            </q-badge>
            <!-- Tag chips -->
            <q-chip v-for="tag in account.tags" :key="tag.id" dense size="sm"
              :style="{ background: tag.color + '33', color: tag.color }">
              {{ tag.name }}
            </q-chip>
          </div>
        </div>
        <div class="row q-gutter-xs items-center flex-wrap">
          <!-- Favourite toggle -->
          <q-btn flat round
            :icon="account.is_favorite ? 'star' : 'star_outline'"
            :color="account.is_favorite ? 'amber-8' : 'grey-5'"
            @click="toggleFav">
            <q-tooltip>{{ account.is_favorite ? 'Remove favourite' : 'Mark as favourite' }}</q-tooltip>
          </q-btn>
          <!-- Clone -->
          <q-btn flat round icon="content_copy" color="grey-6" @click="cloneAccount">
            <q-tooltip>Clone account</q-tooltip>
          </q-btn>
          <q-btn unelevated color="primary" icon="edit" label="Edit" no-caps @click="openEdit" :disable="!account.can_edit" />
          <q-btn flat icon="delete_outline" color="negative" no-caps label="Delete" @click="confirmDelete" :disable="!account.is_owner" />
        </div>
      </div>

      <!-- Tabs -->
      <q-tabs v-model="tab" dense align="left" class="q-mb-sm"
        active-color="primary" indicator-color="primary">
        <q-tab name="details" icon="info_outline" label="Details" no-caps />
        <q-tab v-if="store.hasPermission('acc_view_history')"
          name="history" icon="history" label="History" no-caps />
      </q-tabs>

      <q-tab-panels v-model="tab" animated keep-alive>
        <!-- ── Details panel ── -->
        <q-tab-panel name="details" class="q-pa-none">
          <div class="sp-detail-grid">
            <!-- Password field -->
            <div class="sp-field-card sp-field-card--password">
              <div class="sp-field-label">Password</div>
              <div class="sp-field-row">
                <div class="sp-field-value sp-field-value--mono">
                  {{ showPwd ? decryptedPwd : '••••••••••••' }}
                </div>
                <div class="row q-gutter-xs">
                  <q-btn flat round dense size="sm"
                    :icon="showPwd ? 'visibility_off' : 'visibility'"
                    color="grey-6" @click="togglePassword" :loading="pwdLoading">
                    <q-tooltip>{{ showPwd ? 'Hide' : 'Reveal' }}</q-tooltip>
                  </q-btn>
                  <q-btn flat round dense size="sm"
                    :icon="copied ? 'check' : 'content_copy'"
                    :color="copied ? 'positive' : 'grey-6'"
                    @click="copyPassword" :loading="pwdLoading">
                    <q-tooltip>Copy to clipboard</q-tooltip>
                  </q-btn>
                </div>
              </div>
              <!-- Expiry warning -->
              <div v-if="isExpiringSoon" class="sp-expiry-warn q-mt-sm">
                <q-icon name="schedule" size="14px" class="q-mr-xs" />
                Password change recommended — expires {{ passExpiryLabel }}
              </div>
            </div>

            <!-- Login -->
            <div class="sp-field-card" v-if="account.login">
              <div class="sp-field-label">Username / Login</div>
              <div class="sp-field-row">
                <div class="sp-field-value">{{ account.login }}</div>
                <q-btn flat round dense size="sm" icon="content_copy" color="grey-6"
                  @click="copyText(account.login)">
                  <q-tooltip>Copy</q-tooltip>
                </q-btn>
              </div>
            </div>

            <!-- URL -->
            <div class="sp-field-card" v-if="account.url">
              <div class="sp-field-label">URL</div>
              <div class="sp-field-row">
                <a :href="safeUrl" target="_blank" rel="noopener" class="sp-field-link">
                  {{ account.url }}
                </a>
                <q-btn flat round dense size="sm" icon="open_in_new" color="grey-6"
                  @click="openUrl">
                  <q-tooltip>Open</q-tooltip>
                </q-btn>
              </div>
            </div>

            <!-- Tags detail -->
            <div class="sp-field-card" v-if="account.tags && account.tags.length">
              <div class="sp-field-label">Tags</div>
              <div class="row q-gutter-xs q-mt-xs">
                <q-chip v-for="tag in account.tags" :key="tag.id" dense
                  :style="{ background: tag.color + '33', color: tag.color }">
                  {{ tag.name }}
                </q-chip>
              </div>
            </div>

            <!-- Notes -->
            <div class="sp-field-card sp-field-card--wide" v-if="account.notes">
              <div class="sp-field-label">Notes</div>
              <div class="sp-field-value sp-field-value--notes">{{ account.notes }}</div>
            </div>

            <!-- Meta info -->
            <div class="sp-field-card sp-field-card--wide sp-field-card--meta">
              <div class="sp-meta-row">
                <div class="sp-meta-item">
                  <div class="sp-field-label">Created</div>
                  <div class="sp-field-value text-grey-7">{{ formatDate(account.created_at) }}</div>
                </div>
                <div class="sp-meta-item" v-if="account.updated_at">
                  <div class="sp-field-label">Last modified</div>
                  <div class="sp-field-value text-grey-7">{{ formatDate(account.updated_at) }}</div>
                </div>
                <div class="sp-meta-item">
                  <div class="sp-field-label">Views</div>
                  <div class="sp-field-value">
                    <q-icon name="visibility" size="14px" color="grey-5" class="q-mr-xs" />
                    {{ account.count_view }}
                  </div>
                </div>
                <div class="sp-meta-item">
                  <div class="sp-field-label">Decryptions</div>
                  <div class="sp-field-value">
                    <q-icon name="lock_open" size="14px" color="grey-5" class="q-mr-xs" />
                    {{ account.count_decrypt }}
                  </div>
                </div>
                <div class="sp-meta-item" v-if="account.is_favorite">
                  <q-badge color="amber-1" text-color="amber-9">
                    <q-icon name="star" size="12px" class="q-mr-xs" />Favourite
                  </q-badge>
                </div>
              </div>
            </div>

            <div class="sp-field-card">
              <div class="sp-field-label">Access flags</div>
              <div class="row q-gutter-xs q-mt-xs">
                <q-badge v-if="account.other_user_edit" color="teal-1" text-color="teal-8">Shared users can edit</q-badge>
                <q-badge v-if="account.other_user_group_edit" color="deep-purple-1" text-color="deep-purple-8">Shared groups can edit</q-badge>
                <q-badge v-if="account.pass_date_change" color="red-1" text-color="negative">Change by {{ passExpiryExact }}</q-badge>
              </div>
            </div>

            <div class="sp-field-card" v-if="account.shared_users?.length">
              <div class="sp-field-label">Shared users</div>
              <q-list dense class="q-mt-xs">
                <q-item v-for="entry in account.shared_users" :key="`su-${entry.user_id}`" class="q-px-none">
                  <q-item-section>{{ entry.username }}</q-item-section>
                  <q-item-section side>
                    <q-badge :color="entry.is_edit ? 'positive' : 'grey-5'" :label="entry.is_edit ? 'Edit' : 'View'" />
                  </q-item-section>
                </q-item>
              </q-list>
            </div>

            <div class="sp-field-card" v-if="account.shared_groups?.length">
              <div class="sp-field-label">Shared groups</div>
              <q-list dense class="q-mt-xs">
                <q-item v-for="entry in account.shared_groups" :key="`sg-${entry.group_id}`" class="q-px-none">
                  <q-item-section>{{ entry.name }}</q-item-section>
                  <q-item-section side>
                    <q-badge :color="entry.is_edit ? 'positive' : 'grey-5'" :label="entry.is_edit ? 'Edit' : 'View'" />
                  </q-item-section>
                </q-item>
              </q-list>
            </div>

            <!-- Custom fields -->
            <template v-for="def in cfDefs" :key="`cf-${def.id}`">
              <div class="sp-field-card" v-if="cfValues[def.id] || def.is_show">
                <div class="sp-field-label">
                  <q-icon :name="cfIcon(def.type_name)" size="13px" class="q-mr-xs text-grey-5" />
                  {{ def.name }}
                  <q-badge v-if="def.is_required" color="red-1" text-color="negative" class="q-ml-xs" label="required" />
                </div>
                <div class="sp-field-row">
                  <div class="sp-field-value" :class="def.type_name === 'password' ? 'sp-field-value--mono' : ''">
                    <template v-if="def.is_encrypted">
                      <span class="text-grey-5 text-caption"><q-icon name="lock" size="12px" /> encrypted</span>
                    </template>
                    <template v-else-if="cfValues[def.id]?.value">
                      {{ cfValues[def.id].value }}
                    </template>
                    <template v-else>
                      <span class="text-grey-4">—</span>
                    </template>
                  </div>
                  <q-btn v-if="cfValues[def.id]?.value && !def.is_encrypted"
                    flat round dense size="sm" icon="content_copy" color="grey-6"
                    @click="copyText(cfValues[def.id].value)">
                    <q-tooltip>Copy</q-tooltip>
                  </q-btn>
                </div>
                <div v-if="def.help" class="text-caption text-grey-5 q-mt-xs">{{ def.help }}</div>
              </div>
            </template>
          </div>
        </q-tab-panel>

        <!-- ── History panel ── -->
        <q-tab-panel v-if="store.hasPermission('acc_view_history')" name="history" class="q-pa-none">
          <div v-if="historyLoading" class="sp-center-state">
            <q-spinner-dots size="36px" color="primary" />
          </div>
          <div v-else-if="historyError" class="sp-center-state text-negative">
            <q-icon name="error_outline" size="48px" />
            <div class="text-body2 q-mt-md">{{ historyError }}</div>
          </div>
          <div v-else-if="!history.length" class="sp-center-state">
            <q-icon name="history" size="48px" color="grey-3" />
            <div class="text-body2 text-grey-5 q-mt-md">No history recorded yet</div>
          </div>
          <div v-else class="sp-history-list">
            <div v-for="entry in history" :key="entry.id" class="sp-history-item">
              <q-icon :name="historyIcon(entry.action)" size="18px"
                :color="historyColor(entry.action)" class="sp-history-icon" />
              <div class="sp-history-body">
                <div class="sp-history-action">
                  <span class="sp-history-badge" :class="`sp-history-badge--${entry.action}`">
                    {{ entry.action }}
                  </span>
                  <span v-if="entry.old_value || entry.new_value" class="text-grey-6 text-caption q-ml-sm">
                    <template v-if="entry.old_value && entry.new_value">
                      {{ entry.old_value }} → {{ entry.new_value }}
                    </template>
                    <template v-else-if="entry.new_value">{{ entry.new_value }}</template>
                  </span>
                </div>
                <div class="sp-history-time text-grey-5 text-caption">
                  {{ formatDate(entry.date_add) }}
                </div>
              </div>
            </div>
          </div>
        </q-tab-panel>
      </q-tab-panels>
    </div>

    <!-- ── Edit dialog ── -->
    <q-dialog v-model="showEdit" persistent>
      <q-card style="min-width: 540px; max-width: 95vw">
        <q-card-section class="row items-center q-pb-none">
          <div class="text-h6">Edit account</div>
          <q-space />
          <q-btn flat round dense icon="close" v-close-popup />
        </q-card-section>
        <q-card-section class="q-pt-md q-gutter-y-sm">
          <q-input v-model="editForm.title" label="Name *" outlined dense />
          <div class="row q-gutter-sm">
            <q-input v-model="editForm.login" label="Username / Login" outlined dense class="col" />
            <q-input v-model="editForm.password"
              :type="showEditPwd ? 'text' : 'password'"
              label="New password (leave blank to keep)"
              outlined dense class="col">
              <template v-slot:append>
                <PasswordGenerator @use="editForm.password = $event; showEditPwd = true" />
                <q-icon :name="showEditPwd ? 'visibility_off' : 'visibility'"
                  class="cursor-pointer" color="grey-5" @click="showEditPwd = !showEditPwd" />
              </template>
            </q-input>
          </div>
          <q-input v-model="editForm.url" label="URL" outlined dense />
          <q-select v-model="editForm.category_id" :options="catOpts" option-label="name"
            option-value="id" label="Category" outlined dense emit-value map-options clearable
            use-input hide-selected fill-input input-debounce="0" @filter="filterCats" />
          <!-- Tags -->
          <q-select v-model="editForm.tag_ids" :options="tagOpts" option-label="name" option-value="id"
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
          <q-input v-model="editForm.notes" label="Notes" outlined dense type="textarea" rows="3" />
          <q-toggle v-model="editForm.is_public" label="Public (visible to all users)" />
          <q-toggle v-model="editForm.is_private_group" label="Private to owning group" />
          <q-toggle v-model="editForm.other_user_edit" label="Allow direct shared users to edit" />
          <q-toggle v-model="editForm.other_user_group_edit" label="Allow shared groups to edit" />
          <q-input v-model="editForm.pass_date_change_date" label="Password change date" outlined dense type="date" />

          <q-select
            :model-value="editForm.shared_users.map(entry => entry.user_id)"
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
            @update:model-value="updateEditSharedUsers"
          />
          <div v-if="editForm.shared_users.length" class="q-gutter-sm">
            <div v-for="entry in editForm.shared_users" :key="`eu-${entry.user_id}`" class="row items-center justify-between bg-grey-1 rounded-borders q-px-sm q-py-xs">
              <div class="text-body2">{{ userLabel(entry.user_id) }}</div>
              <q-toggle v-model="entry.is_edit" dense label="Can edit" />
            </div>
          </div>

          <q-select
            :model-value="editForm.shared_groups.map(entry => entry.group_id)"
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
            @update:model-value="updateEditSharedGroups"
          />
          <div v-if="editForm.shared_groups.length" class="q-gutter-sm">
            <div v-for="entry in editForm.shared_groups" :key="`eg-${entry.group_id}`" class="row items-center justify-between bg-grey-1 rounded-borders q-px-sm q-py-xs">
              <div class="text-body2">{{ groupLabel(entry.group_id) }}</div>
              <q-toggle v-model="entry.is_edit" dense label="Can edit" />
            </div>
          </div>
        </q-card-section>
        <!-- Custom fields section in edit dialog -->
        <template v-if="cfDefs.length">
          <q-separator />
          <q-card-section class="q-pt-sm q-pb-xs">
            <div class="text-caption text-grey-6 q-mb-sm text-weight-medium">CUSTOM FIELDS</div>
            <div class="q-gutter-y-sm">
              <div v-for="def in cfDefs.filter(d => !d.is_encrypted)" :key="`cfe-${def.id}`">
                <q-input
                  v-model="cfEdit[def.id]"
                  :label="def.name + (def.is_required ? ' *' : '')"
                  :type="cfInputType(def.type_name)"
                  outlined dense
                  :hint="def.help || undefined"
                >
                  <template v-slot:prepend>
                    <q-icon :name="cfIcon(def.type_name)" size="16px" color="grey-5" />
                  </template>
                </q-input>
              </div>
              <div v-if="cfDefs.some(d => d.is_encrypted)" class="text-caption text-grey-5">
                <q-icon name="lock" size="12px" /> Encrypted fields can only be edited via sysPass PHP.
              </div>
            </div>
          </q-card-section>
        </template>

        <q-card-actions align="right" class="q-pa-md">
          <q-btn flat label="Cancel" v-close-popup />
          <q-btn unelevated color="primary" label="Save changes" :loading="editSaving" no-caps @click="saveEdit" />
        </q-card-actions>
      </q-card>
    </q-dialog>
  </q-page>
</template>

<script setup>
import { ref, computed, onMounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Notify, Dialog } from 'quasar'
import api from '@/api/axios'
import { useMainStore } from '@/stores'
import { encryptPassword } from '@/composables/useClientEncryption'
import PasswordGenerator from '@/components/PasswordGenerator.vue'

const route = useRoute()
const router = useRouter()
const store = useMainStore()

const account = ref(null)
const categories = ref([])
const allTags = ref([])
const users = ref([])
const groups = ref([])
const catOpts = ref([])
const tagOpts = ref([])
const userOptions = ref([])
const groupOptions = ref([])
const history = ref([])
const historyError = ref('')
const loading = ref(true)
const historyLoading = ref(false)
const tab = ref('details')

const showPwd = ref(false)
const decryptedPwd = ref(null)
const pwdLoading = ref(false)
const copied = ref(false)

const showEdit = ref(false)
const showEditPwd = ref(false)
const editSaving = ref(false)
const editForm = ref({ tag_ids: [], shared_users: [], shared_groups: [] })

// ── Custom fields ─────────────────────────────────────────────────────────
const cfDefs   = ref([])   // definitions for module 1 (accounts)
const cfValues = ref({})   // { [def_id]: { value, is_encrypted, name, type_name } }
const cfEdit   = ref({})   // { [def_id]: string } — edit form values

const TYPE_ICONS = {
  text: 'short_text', password: 'lock', date: 'event', number: 'tag',
  email: 'email', telephone: 'phone', url: 'link', color: 'palette',
  wiki: 'menu_book', textarea: 'notes',
}
function cfIcon(typeName) { return TYPE_ICONS[typeName] ?? 'tune' }
function cfInputType(typeName) {
  return { password: 'password', email: 'email', url: 'url',
           number: 'number', date: 'date' }[typeName] ?? 'text'
}

async function loadCustomFields(accountId) {
  try {
    const [defsRes, valsRes] = await Promise.all([
      api.get('/custom-fields/definitions', { params: { module_id: 1 } }),
      api.get(`/custom-fields/values/account/${accountId}`),
    ])
    cfDefs.value = defsRes.data
    const valMap = {}
    for (const v of valsRes.data) valMap[v.def_id] = v
    cfValues.value = valMap
  } catch { /* non-fatal */ }
}

async function saveCustomFields(accountId) {
  const saves = []
  for (const [defId, val] of Object.entries(cfEdit.value)) {
    const v = (val ?? '').toString().trim()
    const existing = cfValues.value[defId]
    if (v === '' && !existing) continue          // nothing to do
    if (v === (existing?.value ?? '')) continue  // no change
    if (v === '') {
      saves.push(api.delete(`/custom-fields/values/${defId}/1/${accountId}`).catch(() => {}))
    } else {
      saves.push(api.post('/custom-fields/values', { def_id: Number(defId), module_id: 1, item_id: accountId, value: v }).catch(() => {}))
    }
  }
  if (saves.length) await Promise.all(saves)
  await loadCustomFields(accountId)
}

// ── Computed ──────────────────────────────────────────────────────────────
const faviconUrl = computed(() => {
  const url = account.value?.url
  if (!url) return null
  try {
    const host = new URL(url.startsWith('http') ? url : `https://${url}`).hostname
    return `https://icons.duckduckgo.com/ip3/${host}.ico`
  } catch { return null }
})

const safeUrl = computed(() => {
  const url = account.value?.url
  if (!url) return '#'
  return url.startsWith('http') ? url : `https://${url}`
})

const categoryLabel = computed(() =>
  categories.value.find(c => c.id === account.value?.category_id)?.name || null
)

const isExpiringSoon = computed(() => {
  const ts = account.value?.pass_date_change
  if (!ts) return false
  const daysLeft = (ts * 1000 - Date.now()) / 86400000
  return daysLeft >= 0 && daysLeft <= 30
})

const passExpiryLabel = computed(() => {
  const ts = account.value?.pass_date_change
  if (!ts) return ''
  const daysLeft = Math.ceil((ts * 1000 - Date.now()) / 86400000)
  if (daysLeft <= 0) return 'today'
  if (daysLeft === 1) return 'tomorrow'
  return `in ${daysLeft} days`
})
const passExpiryExact = computed(() =>
  account.value?.pass_date_change ? formatDate(account.value.pass_date_change * 1000) : ''
)

// ── Helpers ───────────────────────────────────────────────────────────────
function filterCats(val, update) {
  update(() => {
    catOpts.value = val
      ? categories.value.filter(c => c.name.toLowerCase().includes(val.toLowerCase()))
      : [...categories.value]
  })
}
function filterTags(val, update) {
  update(() => {
    tagOpts.value = val
      ? allTags.value.filter(t => t.name.toLowerCase().includes(val.toLowerCase()))
      : [...allTags.value]
  })
}
function tagColor(opt) {
  if (typeof opt === 'object' && opt?.color) return opt.color
  return allTags.value.find(t => t.id === opt)?.color || '#888'
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
function updateEditSharedUsers(ids) {
  const current = new Map((editForm.value.shared_users || []).map(entry => [entry.user_id, !!entry.is_edit]))
  editForm.value.shared_users = (ids || []).map(userId => ({
    user_id: userId,
    is_edit: current.get(userId) || false,
  }))
}
function updateEditSharedGroups(ids) {
  const current = new Map((editForm.value.shared_groups || []).map(entry => [entry.group_id, !!entry.is_edit]))
  editForm.value.shared_groups = (ids || []).map(groupId => ({
    group_id: groupId,
    is_edit: current.get(groupId) || false,
  }))
}

function formatDate(dt) {
  if (!dt) return '—'
  return new Date(dt).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit'
  })
}

function openUrl() {
  window.open(safeUrl.value, '_blank', 'noopener')
}

function historyIcon(action) {
  const map = {
    create: 'add_circle_outline',
    update: 'edit',
    delete: 'delete_outline',
    view: 'visibility',
    decrypt: 'lock_open',
    password_change: 'password',
    file_upload: 'upload_file',
    file_download: 'download',
  }
  return map[action] || 'history'
}
function historyColor(action) {
  const map = {
    create: 'positive', update: 'primary', delete: 'negative',
    decrypt: 'orange', password_change: 'purple',
  }
  return map[action] || 'grey-5'
}

// ── Password ──────────────────────────────────────────────────────────────
async function fetchPassword() {
  if (decryptedPwd.value !== null) return
  pwdLoading.value = true
  try {
    const r = await api.get(`/accounts/${account.value.id}/password`)
    decryptedPwd.value = r.data.password
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Failed to decrypt', color: 'negative' })
  } finally {
    pwdLoading.value = false
  }
}
async function togglePassword() {
  if (!showPwd.value) await fetchPassword()
  showPwd.value = !showPwd.value
}
async function copyPassword() {
  await fetchPassword()
  if (!decryptedPwd.value) return
  try {
    await navigator.clipboard.writeText(decryptedPwd.value)
    copied.value = true
    setTimeout(() => { copied.value = false }, 2000)
  } catch {
    Notify.create({ message: 'Clipboard not available', color: 'warning' })
  }
}
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text)
    Notify.create({ message: 'Copied', color: 'grey-8', timeout: 1200 })
  } catch {}
}

// ── Favourite toggle ──────────────────────────────────────────────────────
async function toggleFav() {
  try {
    const r = await api.post(`/accounts/${account.value.id}/favorite`)
    account.value.is_favorite = r.data.is_favorite
  } catch (e) {
    Notify.create({ message: 'Failed to update favourite', color: 'negative' })
  }
}

// ── Clone ─────────────────────────────────────────────────────────────────
async function cloneAccount() {
  try {
    const r = await api.post(`/accounts/${account.value.id}/copy`)
    Notify.create({ message: `Cloned as "${r.data.title}"`, color: 'positive' })
    router.push(`/accounts/${r.data.id}`)
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Failed to clone', color: 'negative' })
  }
}

// ── Edit ──────────────────────────────────────────────────────────────────
function openEdit() {
  if (!account.value?.can_edit) return
  editForm.value = {
    title: account.value.title,
    login: account.value.login || '',
    password: '',
    url: account.value.url || '',
    category_id: account.value.category_id,
    notes: account.value.notes || '',
    is_public: account.value.is_public || false,
    is_private_group: account.value.is_private_group || false,
    other_user_edit: account.value.other_user_edit || false,
    other_user_group_edit: account.value.other_user_group_edit || false,
    pass_date_change_date: toDateInput(account.value.pass_date_change),
    tag_ids: (account.value.tags || []).map(t => t.id),
    shared_users: normalizeSharedUsers(account.value.shared_users),
    shared_groups: normalizeSharedGroups(account.value.shared_groups),
  }
  // pre-fill custom field edit values
  const map = {}
  for (const d of cfDefs.value) map[d.id] = cfValues.value[d.id]?.value ?? ''
  cfEdit.value = map
  showEditPwd.value = false
  showEdit.value = true
}

async function saveEdit() {
  if (!editForm.value.title) {
    Notify.create({ message: 'Name is required', color: 'warning' })
    return
  }
  editSaving.value = true
  const payload = { ...editForm.value }
  if (!payload.password) {
    delete payload.password
  } else {
    payload.password = await encryptPassword(payload.password)
  }
  payload.pass_date_change = toUnixTimestamp(editForm.value.pass_date_change_date)
  payload.shared_users = normalizeSharedUsers(editForm.value.shared_users)
  payload.shared_groups = normalizeSharedGroups(editForm.value.shared_groups)
  delete payload.pass_date_change_date
  try {
    const r = await api.put(`/accounts/${account.value.id}`, payload)
    account.value = r.data
    decryptedPwd.value = null
    await saveCustomFields(account.value.id)
    history.value = []
    if (tab.value === 'history') await loadHistory()
    showEdit.value = false
    Notify.create({ message: 'Account updated', color: 'positive' })
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Failed to save', color: 'negative' })
  } finally {
    editSaving.value = false
  }
}

// ── Delete ────────────────────────────────────────────────────────────────
function confirmDelete() {
  Dialog.create({
    title: 'Delete account',
    message: `Delete "${account.value.title}"? This cannot be undone.`,
    cancel: { flat: true },
    ok: { label: 'Delete', color: 'negative', unelevated: true },
    persistent: true,
  }).onOk(async () => {
    try {
      await api.delete(`/accounts/${account.value.id}`)
      Notify.create({ message: 'Account deleted', color: 'positive' })
      router.push('/accounts')
    } catch (e) {
      Notify.create({ message: e.response?.data?.detail || 'Failed to delete', color: 'negative' })
    }
  })
}

// ── History ───────────────────────────────────────────────────────────────
async function loadHistory() {
  if (historyLoading.value || !account.value) return
  historyLoading.value = true
  historyError.value = ''
  try {
    const r = await api.get(`/accounts/${account.value.id}/history`)
    history.value = r.data
  } catch (e) {
    history.value = []
    historyError.value = e.response?.data?.detail || 'Failed to load account history'
  } finally {
    historyLoading.value = false
  }
}

watch(tab, val => {
  if (val === 'history' && !history.value.length) loadHistory()
})

// ── Load ──────────────────────────────────────────────────────────────────
onMounted(async () => {
  const id = route.params.id
  try {
    const [accRes, catRes, tagRes, userRes, groupRes] = await Promise.all([
      api.get(`/accounts/${id}`),
      api.get('/categories'),
      api.get('/tags').catch(() => ({ data: [] })),
      api.get('/users').catch(() => ({ data: [] })),
      api.get('/user-groups').catch(() => ({ data: [] })),
    ])
    account.value = accRes.data
    categories.value = catRes.data
    catOpts.value = [...catRes.data]
    allTags.value = tagRes.data
    tagOpts.value = [...tagRes.data]
    users.value = userRes.data
    userOptions.value = [...userRes.data]
    groups.value = groupRes.data
    groupOptions.value = [...groupRes.data]
    await loadCustomFields(id)
  } catch {
    account.value = null
  } finally {
    loading.value = false
  }
})
</script>

<style lang="scss" scoped>
.sp-detail-page {
  background: var(--sp-content-bg, #f4f6fb);
  min-height: 100vh;
}

.sp-back-bar {
  padding: 16px 24px 0;
}

.sp-center-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 80px 24px;
}

.sp-detail-wrap {
  padding: 12px 24px 40px;
  max-width: 960px;
}

// ── Header strip ──────────────────────────────────────────────────────────
.sp-detail-header {
  display: flex;
  align-items: flex-start;
  gap: 16px;
  background: var(--sp-card-bg, #fff);
  border-radius: 14px;
  padding: 20px 24px;
  box-shadow: 0 1px 4px rgba(0,0,0,.07);
  border: 1px solid rgba(0,0,0,.04);
  margin-bottom: 14px;
  flex-wrap: wrap;
}

.sp-detail-favicon {
  width: 52px;
  height: 52px;
  background: #f0f2f8;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  overflow: hidden;
  flex-shrink: 0;
  margin-top: 2px;

  img { width: 36px; height: 36px; object-fit: contain; }
}

// ── Field grid ────────────────────────────────────────────────────────────
.sp-detail-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;

  @media (max-width: 600px) { grid-template-columns: 1fr; }
}

.sp-field-card {
  background: var(--sp-card-bg, #fff);
  border-radius: 12px;
  padding: 16px 20px;
  box-shadow: 0 1px 4px rgba(0,0,0,.06);
  border: 1px solid rgba(0,0,0,.04);

  &--wide { grid-column: 1 / -1; }
  &--password { border-left: 3px solid var(--sp-accent-color, #1a237e); }
  &--meta { background: var(--sp-card-bg-alt, #f9fafc); box-shadow: none; }
}

.sp-field-label {
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .6px;
  text-transform: uppercase;
  color: var(--sp-text-secondary, #9ca3af);
  margin-bottom: 6px;
}

.sp-field-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.sp-field-value {
  font-size: 15px;
  color: var(--sp-text-primary, #111827);
  word-break: break-all;

  &--mono {
    font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
    font-size: 16px;
    letter-spacing: 1px;
  }
  &--notes {
    font-size: 14px;
    color: var(--sp-text-secondary, #4b5563);
    white-space: pre-wrap;
    line-height: 1.6;
  }
}

.sp-field-link {
  color: var(--sp-accent-color, #1a237e);
  text-decoration: none;
  font-size: 14px;
  word-break: break-all;
  &:hover { text-decoration: underline; }
}

.sp-expiry-warn {
  font-size: 12px;
  color: #dc2626;
  display: flex;
  align-items: center;
}

.sp-meta-row {
  display: flex;
  gap: 28px;
  flex-wrap: wrap;
  align-items: center;
}
.sp-meta-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

// ── History ───────────────────────────────────────────────────────────────
.sp-history-list {
  display: flex;
  flex-direction: column;
  gap: 0;
  background: var(--sp-card-bg, #fff);
  border-radius: 12px;
  box-shadow: 0 1px 4px rgba(0,0,0,.06);
  border: 1px solid rgba(0,0,0,.04);
  overflow: hidden;
}

.sp-history-item {
  display: flex;
  align-items: flex-start;
  gap: 14px;
  padding: 14px 20px;
  border-bottom: 1px solid rgba(0,0,0,.05);

  &:last-child { border-bottom: none; }
}

.sp-history-icon { flex-shrink: 0; margin-top: 2px; }

.sp-history-body { flex: 1; min-width: 0; }

.sp-history-action { display: flex; align-items: center; flex-wrap: wrap; gap: 6px; }

.sp-history-badge {
  display: inline-block;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .4px;
  text-transform: uppercase;
  padding: 2px 8px;
  border-radius: 4px;
  background: #e5e7eb;
  color: #374151;

  &--create { background: #d1fae5; color: #065f46; }
  &--update { background: #dbeafe; color: #1e40af; }
  &--delete { background: #fee2e2; color: #991b1b; }
  &--decrypt, &--view { background: #fef3c7; color: #92400e; }
  &--password_change { background: #ede9fe; color: #6d28d9; }
}

.sp-history-time { margin-top: 3px; }
</style>
