import { createRouter, createWebHistory } from 'vue-router'
import api from '@/api/axios'
import routes from './routes'

const router = createRouter({
  history: createWebHistory(),
  routes
})

let installStatusPromise = null

async function getInstallStatus() {
  if (!installStatusPromise) {
    installStatusPromise = api
      .get('/auth/install/status')
      .then(response => response.data)
      .catch(() => ({ installed: true }))
      .finally(() => {
        installStatusPromise = null
      })
  }
  return installStatusPromise
}

router.beforeEach(async (to, from, next) => {
  const requiresAuth = to.matched.some(record => record.meta.requiresAuth)
  const token = localStorage.getItem('auth_token')
  const installStatus = await getInstallStatus()
  const installRoute = to.path === '/install' || to.path === '/register'

  if (!installStatus.installed && !installRoute) {
    next('/install')
    return
  }

  if (installStatus.installed && installRoute) {
    next(token ? '/accounts' : '/login')
    return
  }

  if (requiresAuth && !token) {
    next('/login')
  } else if (to.path === '/login' && token) {
    next('/accounts')
  } else {
    next()
  }
})

export default router
