export default [
  {
    path: '/login',
    name: 'login',
    component: () => import('../views/LoginPage.vue'),
    meta: { requiresAuth: false }
  },
  {
    path: '/install',
    name: 'install',
    component: () => import('../views/RegisterPage.vue'),
    meta: { requiresAuth: false }
  },
  {
    path: '/register',
    name: 'register',
    component: () => import('../views/RegisterPage.vue'),
    meta: { requiresAuth: false }
  },
  {
    path: '/password-reset',
    name: 'password-reset',
    component: () => import('../views/PasswordResetPage.vue'),
    meta: { requiresAuth: false }
  },
  {
    path: '/',
    component: () => import('../layouts/MainLayout.vue'),
    meta: { requiresAuth: true },
    children: [
      {
        path: '',
        redirect: '/accounts'
      },
      {
        path: 'accounts',
        name: 'accounts',
        component: () => import('../views/AccountsPage.vue')
      },
      {
        path: 'accounts/:id',
        name: 'account-detail',
        component: () => import('../views/AccountDetailPage.vue')
      },
      {
        path: 'categories',
        name: 'categories',
        component: () => import('../views/CategoriesPage.vue')
      },
      {
        path: 'clients',
        name: 'clients',
        component: () => import('../views/ClientsPage.vue')
      },
      {
        path: 'tags',
        name: 'tags',
        component: () => import('../views/TagsPage.vue')
      },
      {
        path: 'users',
        name: 'users',
        component: () => import('../views/UsersPage.vue')
      },
      {
        path: 'user-groups',
        name: 'user-groups',
        component: () => import('../views/UserGroupsPage.vue')
      },
      {
        path: 'user-profiles',
        name: 'user-profiles',
        component: () => import('../views/UserProfilesPage.vue')
      },
      {
        path: 'notifications',
        name: 'notifications',
        component: () => import('../views/NotificationsPage.vue')
      },
      {
        path: 'settings',
        name: 'settings',
        component: () => import('../views/SettingsPage.vue')
      },
      {
        path: 'profile',
        name: 'profile',
        component: () => import('../views/UserProfilePage.vue')
      },
      {
        path: 'api-authorizations',
        name: 'api-authorizations',
        component: () => import('../views/ApiAuthorizationsPage.vue')
      },
      {
        path: 'custom-fields',
        name: 'custom-fields',
        component: () => import('../views/CustomFieldsPage.vue')
      },
      {
        path: 'event-log',
        name: 'event-log',
        component: () => import('../views/EventLogPage.vue')
      },
      {
        path: 'tracks',
        name: 'tracks',
        component: () => import('../views/TracksPage.vue')
      },
      {
        path: 'item-presets',
        name: 'item-presets',
        component: () => import('../views/ItemPresetsPage.vue')
      },
      {
        path: 'backup',
        name: 'backup',
        component: () => import('../views/BackupPage.vue')
      },
      {
        path: 'plugins',
        name: 'plugins',
        component: () => import('../views/PluginsPage.vue')
      }
    ]
  },
  {
    path: '/:pathMatch(.*)*',
    redirect: to => {
      const token = localStorage.getItem('auth_token')
      return token ? '/accounts' : '/login'
    }
  }
]
