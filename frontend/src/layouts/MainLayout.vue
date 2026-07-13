<template>
  <q-layout view="hHh LpR fFf">
    <!-- ── Header ── -->
    <q-header class="sp-header" :style="{ backgroundColor: currentTheme.headerBg }">
      <q-toolbar>
        <q-btn flat dense round icon="menu" @click="toggleDrawer" class="q-mr-sm" />

        <div class="sp-logo row items-center no-wrap">
          <q-icon name="shield" size="22px" class="q-mr-xs" />
          <span class="sp-logo-text">sys<strong>Pass</strong></span>
        </div>

        <q-space />

        <template v-if="store.isAuthenticated">
          <!-- Search trigger -->
          <q-btn flat round icon="search" class="q-mr-xs" @click="$router.push('/accounts')" />

          <!-- Notifications -->
          <q-btn flat round icon="notifications_none" class="q-mr-xs" @click="$router.push('/notifications')">
            <q-badge v-if="unreadCount > 0" color="red" floating :label="unreadCount" />
          </q-btn>

          <!-- User menu -->
          <q-btn-dropdown flat no-caps padding="4px 8px">
            <template v-slot:label>
              <q-avatar size="32px" color="white" text-color="primary" class="text-weight-bold">
                {{ userInitial }}
              </q-avatar>
            </template>
            <q-list dense style="min-width: 210px">
              <q-item-label header class="text-grey-6 text-caption">
                {{ store.currentUser?.username }}
              </q-item-label>
              <q-separator />

              <q-item clickable v-ripple @click="$router.push('/profile')" v-close-popup>
                <q-item-section avatar><q-icon name="manage_accounts" size="sm" /></q-item-section>
                <q-item-section>My Profile</q-item-section>
              </q-item>

              <!-- Theme picker -->
              <q-separator />
              <q-item-label header class="text-grey-6 text-caption" style="padding-bottom: 6px">
                Theme
              </q-item-label>
              <q-item class="q-pb-sm">
                <q-item-section>
                  <div class="sp-swatch-row">
                    <button
                      v-for="t in themes"
                      :key="t.id"
                      class="sp-swatch"
                      :class="{ 'sp-swatch--active': activeTheme === t.id }"
                      :style="{ background: t.swatch }"
                      :title="t.label"
                      @click="selectTheme(t.id)"
                    />
                  </div>
                  <div class="text-caption text-grey-6 q-mt-xs">{{ activeThemeLabel }}</div>
                </q-item-section>
              </q-item>

              <q-separator />
              <q-item clickable v-ripple @click="logout" v-close-popup class="text-negative">
                <q-item-section avatar><q-icon name="logout" size="sm" color="negative" /></q-item-section>
                <q-item-section>Sign out</q-item-section>
              </q-item>
            </q-list>
          </q-btn-dropdown>
        </template>
      </q-toolbar>
    </q-header>

    <!-- ── Sidebar ── -->
    <q-drawer v-model="drawerOpen" show-if-above :width="232" :mini="miniMode" :mini-width="56" class="sp-drawer"
      :style="{ backgroundColor: currentTheme.sidebarBg, color: '#fff' }">
      <!-- Mini toggle -->
      <div class="sp-mini-toggle" v-if="!$q.screen.lt.md">
        <q-btn flat round dense :icon="miniMode ? 'chevron_right' : 'chevron_left'"
          size="sm" @click="miniMode = !miniMode" class="text-white opacity-60" />
      </div>

      <q-scroll-area class="fit">
        <q-list class="sp-nav" :class="{ 'sp-nav--mini': miniMode }">

          <!-- Search -->
          <sp-nav-item icon="search" label="Search" to="/accounts" :active="false" :mini="miniMode" />

          <!-- New Account -->
          <sp-nav-item icon="add_circle_outline" label="New Account" :active="false" :mini="miniMode"
            @click="$router.push('/accounts?create=1')" />

          <q-separator class="sp-sep" />

          <!-- Users & Access -->
          <template v-if="miniMode && (store.hasPermission('mgm_users') || store.hasPermission('mgm_groups') || store.hasPermission('mgm_profiles') || store.hasPermission('mgm_api_tokens'))">
            <sp-nav-item v-if="store.hasPermission('mgm_users')" icon="people_outline" label="Users" to="/users" :active="$route.name === 'users'" :mini="true" />
            <sp-nav-item v-if="store.hasPermission('mgm_groups')" icon="group_work" label="Groups" to="/user-groups" :active="$route.name === 'user-groups'" :mini="true" />
            <sp-nav-item v-if="store.hasPermission('mgm_profiles')" icon="badge" label="Profiles" to="/user-profiles" :active="$route.name === 'user-profiles'" :mini="true" />
            <sp-nav-item v-if="store.hasPermission('mgm_api_tokens')" icon="vpn_key" label="API Authorizations" to="/api-authorizations" :active="$route.name === 'api-authorizations'" :mini="true" />
            <q-separator class="sp-sep" />
          </template>
          <q-expansion-item
            v-if="!miniMode && (store.hasPermission('mgm_users') || store.hasPermission('mgm_groups') || store.hasPermission('mgm_profiles') || store.hasPermission('mgm_api_tokens'))"
            icon="manage_accounts" label="Users & Access" class="sp-expand"
            header-class="sp-expand-header"
            :default-opened="usersGroupOpen">
            <sp-nav-item v-if="store.hasPermission('mgm_users')" icon="people_outline" label="Users" to="/users" :active="$route.name === 'users'" indent />
            <sp-nav-item v-if="store.hasPermission('mgm_groups')" icon="group_work" label="Groups" to="/user-groups" :active="$route.name === 'user-groups'" indent />
            <sp-nav-item v-if="store.hasPermission('mgm_profiles')" icon="badge" label="Profiles" to="/user-profiles" :active="$route.name === 'user-profiles'" indent />
            <sp-nav-item v-if="store.hasPermission('mgm_api_tokens')" icon="vpn_key" label="API Authorizations" to="/api-authorizations" :active="$route.name === 'api-authorizations'" indent />
          </q-expansion-item>

          <!-- Items & Customizations -->
          <template v-if="miniMode && (store.hasPermission('mgm_categories') || store.hasPermission('mgm_tags') || store.hasPermission('mgm_customers') || store.hasPermission('mgm_custom_fields'))">
            <sp-nav-item v-if="store.hasPermission('mgm_categories')" icon="folder_open" label="Categories" to="/categories" :active="$route.name === 'categories'" :mini="true" />
            <sp-nav-item v-if="store.hasPermission('mgm_tags')" icon="label_outline" label="Tags" to="/tags" :active="$route.name === 'tags'" :mini="true" />
            <sp-nav-item v-if="store.hasPermission('mgm_customers')" icon="business_center" label="Clients" to="/clients" :active="$route.name === 'clients'" :mini="true" />
            <sp-nav-item v-if="store.hasPermission('mgm_custom_fields')" icon="tune" label="Custom Fields" to="/custom-fields" :active="$route.name === 'custom-fields'" :mini="true" />
            <q-separator class="sp-sep" />
          </template>
          <q-expansion-item
            v-if="!miniMode && (store.hasPermission('mgm_categories') || store.hasPermission('mgm_tags') || store.hasPermission('mgm_customers') || store.hasPermission('mgm_custom_fields'))"
            icon="category" label="Items & Customizations" class="sp-expand"
            header-class="sp-expand-header"
            :default-opened="itemsGroupOpen">
            <sp-nav-item v-if="store.hasPermission('mgm_categories')" icon="folder_open" label="Categories" to="/categories" :active="$route.name === 'categories'" indent />
            <sp-nav-item v-if="store.hasPermission('mgm_tags')" icon="label_outline" label="Tags" to="/tags" :active="$route.name === 'tags'" indent />
            <sp-nav-item v-if="store.hasPermission('mgm_customers')" icon="business_center" label="Clients" to="/clients" :active="$route.name === 'clients'" indent />
            <sp-nav-item v-if="store.hasPermission('mgm_custom_fields')" icon="tune" label="Custom Fields" to="/custom-fields" :active="$route.name === 'custom-fields'" indent />
          </q-expansion-item>

          <!-- Security & Audit -->
          <template v-if="miniMode">
            <sp-nav-item icon="notifications_none" label="Notifications" to="/notifications"
              :active="$route.name === 'notifications'" :badge="unreadCount" :mini="true" />
            <sp-nav-item v-if="store.hasPermission('evl')" icon="history" label="Event Log" to="/event-log"
              :active="$route.name === 'event-log'" :mini="true" />
            <sp-nav-item v-if="store.hasPermission('evl')" icon="track_changes" label="Tracks" to="/tracks"
              :active="$route.name === 'tracks'" :mini="true" />
            <q-separator class="sp-sep" />
          </template>
          <q-expansion-item v-if="!miniMode" icon="security" label="Security & Audit" class="sp-expand"
            header-class="sp-expand-header"
            :default-opened="securityGroupOpen">
            <sp-nav-item icon="notifications_none" label="Notifications" to="/notifications"
              :active="$route.name === 'notifications'" :badge="unreadCount" indent />
            <sp-nav-item v-if="store.hasPermission('evl')" icon="history" label="Event Log" to="/event-log"
              :active="$route.name === 'event-log'" indent />
            <sp-nav-item v-if="store.hasPermission('evl')" icon="track_changes" label="Tracks" to="/tracks"
              :active="$route.name === 'tracks'" indent />
          </q-expansion-item>

          <!-- Plugins (admin only — no profile permission for this) -->
          <sp-nav-item v-if="store.isAdmin" icon="extension" label="Plugins" to="/plugins" :active="$route.name === 'plugins'" :mini="miniMode" />

          <q-separator class="sp-sep" />

          <!-- Configuration -->
          <sp-nav-item
            v-if="store.hasPermission('config_general') || store.hasPermission('config_encryption') || store.hasPermission('config_backup') || store.hasPermission('config_import')"
            icon="tune" label="Configuration" to="/settings" :active="$route.name === 'settings'" :mini="miniMode" />

        </q-list>
      </q-scroll-area>
    </q-drawer>

    <!-- ── Content ── -->
    <q-page-container class="sp-content">
      <router-view />
    </q-page-container>
  </q-layout>
</template>

<script setup>
import { ref, computed, onMounted, defineComponent, h } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useQuasar } from 'quasar'
import { useMainStore } from '@/stores'
import { Notify } from 'quasar'
import api from '@/api/axios'
import { themes, applyTheme, getSavedTheme } from '@/composables/useTheme'

// ── Inline nav-item component ─────────────────────────────────────────────
const SpNavItem = defineComponent({
  name: 'SpNavItem',
  props: {
    icon: String,
    label: String,
    to: String,
    active: Boolean,
    badge: { type: Number, default: 0 },
    indent: Boolean,
    mini: Boolean,
    disabled: Boolean,
  },
  emits: ['click'],
  setup(props, { emit }) {
    const router = useRouter()
    function handleClick() {
      if (props.disabled) return
      if (props.to) router.push(props.to)
      else emit('click')
    }
    return () => {
      const classes = [
        'sp-nav-item',
        props.active ? 'sp-nav-item--active' : '',
        props.indent ? 'sp-nav-item--indent' : '',
        props.mini ? 'sp-nav-item--mini' : '',
        props.disabled ? 'sp-nav-item--disabled' : '',
      ].filter(Boolean)

      const children = props.mini
        ? [h('q-icon', { name: props.icon, size: '20px', class: 'sp-nav-icon' })]
        : [
            h('q-icon', { name: props.icon, size: '18px', class: 'sp-nav-icon' }),
            h('span', { class: 'sp-nav-label' }, props.label),
            props.badge > 0
              ? h('span', { class: 'sp-nav-badge' }, String(props.badge))
              : null,
          ]

      const tooltip = props.mini
        ? [h('q-tooltip', { anchor: 'center right', self: 'center left', offset: [8, 0] }, props.label)]
        : []

      return h('div', { class: classes, onClick: handleClick }, [...children, ...tooltip])
    }
  },
})

// ── Layout state ──────────────────────────────────────────────────────────
const $q = useQuasar()
const router = useRouter()
const route = useRoute()
const store = useMainStore()

const drawerOpen = ref(true)
const miniMode = ref(false)
const unreadCount = ref(0)
const activeTheme = ref(getSavedTheme())

const usersGroupOpen = computed(() =>
  ['users', 'user-groups', 'user-profiles', 'api-authorizations'].includes(route.name)
)
const itemsGroupOpen = computed(() =>
  ['categories', 'clients', 'tags', 'custom-fields'].includes(route.name)
)
const securityGroupOpen = computed(() =>
  ['notifications', 'event-log', 'tracks'].includes(route.name)
)

const currentTheme = computed(() =>
  themes.find(t => t.id === activeTheme.value) ?? themes[0]
)

const userInitial = computed(() => {
  const u = store.currentUser?.username || '?'
  return u.charAt(0).toUpperCase()
})

const activeThemeLabel = computed(() => currentTheme.value.label)

function toggleDrawer() {
  if ($q.screen.lt.md) {
    drawerOpen.value = !drawerOpen.value
  } else {
    miniMode.value = !miniMode.value
  }
}

function selectTheme(id) {
  activeTheme.value = id
  applyTheme(id)
}

async function fetchNotifications() {
  try {
    const r = await api.get('/notifications/unread-count')
    unreadCount.value = r.data.unread_count
  } catch { /* silent */ }
}

function logout() {
  store.clearToken()
  Notify.create({ message: 'Signed out', color: 'grey-8', icon: 'logout' })
  router.push('/login')
}

async function fetchCurrentUser() {
  if (store.currentUser) return
  try {
    const r = await api.get('/auth/me')
    store.setUser({
      id: r.data.id,
      username: r.data.username,
      is_admin: r.data.is_admin ?? false,
      permissions: r.data.permissions ?? null,
    })
  } catch { /* silent — user will just see no items */ }
}

onMounted(() => {
  if (store.isAuthenticated) {
    fetchCurrentUser()
    fetchNotifications()
    setInterval(fetchNotifications, 30000)
  }
})
</script>

<style lang="scss" scoped>
// ── Header ────────────────────────────────────────────────────────────────
.sp-header {
  box-shadow: 0 1px 8px rgba(0,0,0,.35);
}

.sp-logo {
  font-size: 18px;
  color: #fff;
  letter-spacing: -.3px;

  &-text {
    font-weight: 300;
    strong { font-weight: 700; }
  }
}

// ── Drawer / Sidebar ─────────────────────────────────────────────────────
.sp-drawer {
  color: #fff;
}

.sp-mini-toggle {
  position: absolute;
  bottom: 16px;
  right: 4px;
  z-index: 10;
}

.sp-nav {
  padding: 12px 0 60px;
}

.sp-nav-section {
  padding: 16px 16px 4px;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 1px;
  text-transform: uppercase;
  color: rgba(255,255,255,.35);
}

.sp-sep {
  margin: 12px 0;
  background: rgba(255,255,255,.08);
}

// ── Theme swatches ────────────────────────────────────────────────────────
.sp-swatch-row {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}

.sp-swatch {
  width: 22px;
  height: 22px;
  border-radius: 50%;
  border: 2px solid transparent;
  cursor: pointer;
  transition: transform .15s, border-color .15s;
  padding: 0;

  &:hover { transform: scale(1.15); }

  &--active {
    border-color: #fff;
    box-shadow: 0 0 0 2px rgba(0,0,0,.3);
    transform: scale(1.1);
  }
}
</style>

<!-- Unscoped so the dynamic component picks it up -->
<style lang="scss">
.sp-nav-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 14px;
  margin: 1px 8px;
  border-radius: 8px;
  cursor: pointer;
  transition: background .15s, color .15s;
  color: rgba(255,255,255,.65);
  font-size: 13.5px;
  font-weight: 500;
  white-space: nowrap;
  overflow: hidden;

  &:hover {
    background: rgba(255,255,255,.08);
    color: #fff;
  }

  &--active {
    background: rgba(255,255,255,.12);
    color: #fff;
    border-left: 3px solid var(--sp-accent-color, #5c9dff);
    padding-left: 11px;
    .sp-nav-icon { color: var(--sp-accent-color, #5c9dff) !important; }
  }

  &--indent {
    padding-left: 36px;
    font-size: 13px;
    color: rgba(255,255,255,.55);
    &.sp-nav-item--active { padding-left: 33px; }
  }

  &--mini {
    justify-content: center;
    padding: 10px 0;
    margin: 1px 6px;
    border-radius: 8px;
    gap: 0;
  }

  &--disabled {
    opacity: .35;
    cursor: default;
    pointer-events: none;
  }

  .sp-nav-icon {
    flex-shrink: 0;
    color: rgba(255,255,255,.5);
    transition: color .15s;
  }

  .sp-nav-label {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .sp-nav-badge {
    background: #ef5350;
    color: #fff;
    font-size: 10px;
    font-weight: 700;
    border-radius: 10px;
    padding: 1px 6px;
    min-width: 18px;
    text-align: center;
  }
}

// Expansion item header styled like nav items
.sp-expand {
  margin: 1px 8px;
  border-radius: 8px;
  overflow: hidden;
}

.sp-expand-header {
  color: rgba(255,255,255,.75) !important;
  font-size: 13.5px !important;
  font-weight: 500 !important;
  padding: 8px 14px !important;
  min-height: unset !important;

  .q-item__section--avatar {
    min-width: unset;
    padding-right: 10px;
    color: rgba(255,255,255,.5);
  }
  .q-item__section--side { color: rgba(255,255,255,.4); }

  &:hover {
    background: rgba(255,255,255,.08) !important;
    color: #fff !important;
  }
}

.sp-content {
  background: var(--sp-content-bg, #f4f6fb);
}
</style>
