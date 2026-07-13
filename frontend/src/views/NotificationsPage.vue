<template>
  <q-page class="sp-notif-page">
    <div class="sp-page-header">
      <div>
        <div class="text-h5 text-weight-bold text-grey-9">Notifications</div>
        <div class="text-caption text-grey-6">
          {{ unread }} unread of {{ notifications.length }} total
        </div>
      </div>
      <div class="row q-gutter-sm">
        <q-btn flat no-caps color="grey-7" icon="done_all" label="Mark all read"
          :disable="unread === 0" @click="markAllRead" />
        <q-btn flat no-caps color="negative" icon="delete_sweep" label="Clear all"
          :disable="notifications.length === 0" @click="confirmClearAll" />
      </div>
    </div>

    <!-- Filter tabs -->
    <div class="sp-notif-tabs">
      <button
        v-for="f in filters"
        :key="f.value"
        class="sp-tab-btn"
        :class="{ 'sp-tab-btn--active': activeFilter === f.value }"
        @click="activeFilter = f.value"
      >
        {{ f.label }}
        <span v-if="f.count > 0" class="sp-tab-count">{{ f.count }}</span>
      </button>
    </div>

    <!-- Loading -->
    <div v-if="loading" class="sp-center-state">
      <q-spinner-dots size="48px" color="primary" />
    </div>

    <!-- Empty -->
    <div v-else-if="filtered.length === 0" class="sp-center-state">
      <q-icon name="notifications_none" size="64px" color="grey-3" />
      <div class="text-h6 text-grey-5 q-mt-md">
        {{ activeFilter === 'unread' ? 'All caught up!' : 'No notifications' }}
      </div>
      <div class="text-body2 text-grey-4">Activity events will appear here</div>
    </div>

    <!-- List -->
    <div v-else class="sp-notif-list">
      <div
        v-for="n in filtered"
        :key="n.id"
        class="sp-notif-item"
        :class="{ 'sp-notif-item--unread': !n.is_read }"
        @click="!n.is_read && markRead(n)"
      >
        <!-- Icon -->
        <div class="sp-notif-icon" :class="`sp-notif-icon--${typeColor(n.type)}`">
          <q-icon :name="typeIcon(n.type)" size="20px" />
        </div>

        <!-- Content -->
        <div class="sp-notif-content">
          <div class="sp-notif-message">{{ n.message }}</div>
          <div class="sp-notif-meta">
            <q-badge :color="typeColor(n.type)" class="sp-type-badge">{{ typeLabel(n.type) }}</q-badge>
            <span class="sp-notif-time">{{ timeAgo(n.date_add) }}</span>
          </div>
        </div>

        <!-- Actions -->
        <div class="sp-notif-actions" @click.stop>
          <q-btn flat round dense size="sm" icon="check" color="grey-5"
            v-if="!n.is_read" @click="markRead(n)">
            <q-tooltip>Mark as read</q-tooltip>
          </q-btn>
          <q-btn flat round dense size="sm" icon="close" color="grey-5" @click="deleteOne(n)">
            <q-tooltip>Dismiss</q-tooltip>
          </q-btn>
        </div>

        <!-- Unread dot -->
        <div v-if="!n.is_read" class="sp-notif-dot" />
      </div>
    </div>
  </q-page>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { Notify, Dialog } from 'quasar'
import api from '@/api/axios'

const notifications = ref([])
const loading = ref(true)
const activeFilter = ref('all')

// ── Computed ──────────────────────────────────────────────────────────────
const unread = computed(() => notifications.value.filter(n => !n.is_read).length)

const filtered = computed(() => {
  if (activeFilter.value === 'unread') return notifications.value.filter(n => !n.is_read)
  return notifications.value
})

const filters = computed(() => [
  { label: 'All', value: 'all', count: 0 },
  { label: 'Unread', value: 'unread', count: unread.value },
])

// ── Icon / colour mapping ─────────────────────────────────────────────────
const typeMap = {
  account_created:    { icon: 'add_circle_outline', color: 'positive', label: 'Account' },
  account_updated:    { icon: 'edit',               color: 'info',     label: 'Account' },
  account_deleted:    { icon: 'delete_outline',     color: 'negative', label: 'Account' },
  password_changed:   { icon: 'lock_reset',         color: 'warning',  label: 'Security' },
  file_uploaded:      { icon: 'upload_file',        color: 'info',     label: 'File' },
  file_downloaded:    { icon: 'download',           color: 'info',     label: 'File' },
  login_success:      { icon: 'login',              color: 'positive', label: 'Auth' },
  login_failed:       { icon: 'no_accounts',        color: 'negative', label: 'Auth' },
  two_factor_enabled: { icon: 'verified_user',      color: 'positive', label: 'Security' },
  two_factor_disabled:{ icon: 'gpp_bad',            color: 'warning',  label: 'Security' },
  public_link_created:{ icon: 'link',               color: 'info',     label: 'Share' },
  system_warning:     { icon: 'warning_amber',      color: 'warning',  label: 'System' },
  system_error:       { icon: 'error_outline',      color: 'negative', label: 'System' },
}

function typeIcon(t)  { return typeMap[t]?.icon  ?? 'notifications_none' }
function typeColor(t) { return typeMap[t]?.color ?? 'grey-6' }
function typeLabel(t) { return typeMap[t]?.label ?? t }

function timeAgo(dt) {
  if (!dt) return ''
  const diff = (Date.now() - new Date(dt).getTime()) / 1000
  if (diff < 60)   return 'just now'
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return new Date(dt).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

// ── Actions ───────────────────────────────────────────────────────────────
async function markRead(n) {
  try {
    await api.post(`/notifications/${n.id}/read`)
    n.is_read = true
  } catch {}
}

async function markAllRead() {
  try {
    await api.post('/notifications/read-all')
    notifications.value.forEach(n => { n.is_read = true })
    Notify.create({ message: 'All marked as read', color: 'grey-8', timeout: 1500 })
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Failed', color: 'negative' })
  }
}

async function deleteOne(n) {
  try {
    await api.delete(`/notifications/${n.id}`)
    notifications.value = notifications.value.filter(x => x.id !== n.id)
  } catch (e) {
    Notify.create({ message: e.response?.data?.detail || 'Failed', color: 'negative' })
  }
}

function confirmClearAll() {
  Dialog.create({
    title: 'Clear all notifications',
    message: 'This will permanently remove all notifications.',
    cancel: { flat: true },
    ok: { label: 'Clear all', color: 'negative', unelevated: true },
  }).onOk(async () => {
    try {
      await api.delete('/notifications')
      notifications.value = []
      Notify.create({ message: 'All notifications cleared', color: 'grey-8', timeout: 1500 })
    } catch (e) {
      Notify.create({ message: e.response?.data?.detail || 'Failed', color: 'negative' })
    }
  })
}

// ── Load ──────────────────────────────────────────────────────────────────
onMounted(async () => {
  try {
    const r = await api.get('/notifications')
    notifications.value = r.data
  } catch {
    Notify.create({ message: 'Failed to load notifications', color: 'negative' })
  } finally {
    loading.value = false
  }
})
</script>

<style lang="scss" scoped>
.sp-notif-page {
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

.sp-center-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 80px 24px;
}

// ── Filter tabs ───────────────────────────────────────────────────────────
.sp-notif-tabs {
  display: flex;
  gap: 4px;
  padding: 16px 24px 0;
  border-bottom: 1px solid var(--sp-border-color, #e5e7eb);
  margin-bottom: 0;
}

.sp-tab-btn {
  padding: 8px 16px;
  border: none;
  background: transparent;
  font-size: 14px;
  font-weight: 500;
  color: var(--sp-text-secondary, #6b7280);
  cursor: pointer;
  border-bottom: 2px solid transparent;
  margin-bottom: -1px;
  transition: color .15s, border-color .15s;
  display: flex;
  align-items: center;
  gap: 6px;
  border-radius: 6px 6px 0 0;

  &:hover { color: var(--sp-accent-color, #1a237e); }

  &--active {
    color: var(--sp-accent-color, #1a237e);
    border-bottom-color: var(--sp-accent-color, #1a237e);
  }
}

.sp-tab-count {
  background: #ef5350;
  color: #fff;
  font-size: 10px;
  font-weight: 700;
  border-radius: 10px;
  padding: 1px 6px;
  min-width: 18px;
  text-align: center;
}

// ── Notification list ─────────────────────────────────────────────────────
.sp-notif-list {
  padding: 12px 24px 32px;
  display: flex;
  flex-direction: column;
  gap: 6px;
  max-width: 800px;
}

.sp-notif-item {
  display: flex;
  align-items: flex-start;
  gap: 14px;
  background: var(--sp-card-bg, #fff);
  border-radius: 12px;
  padding: 14px 16px;
  border: 1px solid rgba(0,0,0,.05);
  box-shadow: 0 1px 3px rgba(0,0,0,.05);
  position: relative;
  cursor: default;
  transition: box-shadow .15s;

  &:hover { box-shadow: 0 2px 8px rgba(0,0,0,.1); }

  &--unread {
    background: var(--sp-card-bg-alt, #fafbff);
    border-left: 3px solid var(--sp-accent-color, #1a237e);
    cursor: pointer;
  }
}

// ── Coloured icon circles ─────────────────────────────────────────────────
.sp-notif-icon {
  width: 38px;
  height: 38px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;

  &--positive  { background: #dcfce7; color: #16a34a; }
  &--negative  { background: #fee2e2; color: #dc2626; }
  &--warning   { background: #fef9c3; color: #ca8a04; }
  &--info      { background: #dbeafe; color: #2563eb; }
  &--grey-6    { background: #f3f4f6; color: #6b7280; }
}

.sp-notif-content { flex: 1; min-width: 0; }

.sp-notif-message {
  font-size: 14px;
  color: var(--sp-text-primary, #111827);
  line-height: 1.4;
}

.sp-notif-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 5px;
}

.sp-type-badge {
  font-size: 10px;
  font-weight: 700;
  padding: 2px 6px;
  border-radius: 4px;
  text-transform: uppercase;
  letter-spacing: .4px;
}

.sp-notif-time {
  font-size: 12px;
  color: var(--sp-text-secondary, #9ca3af);
}

.sp-notif-actions {
  display: flex;
  gap: 2px;
  flex-shrink: 0;
  opacity: 0;
  transition: opacity .15s;
}

.sp-notif-item:hover .sp-notif-actions { opacity: 1; }

.sp-notif-dot {
  position: absolute;
  top: 14px;
  right: 14px;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--sp-accent-color, #1a237e);
}
</style>
