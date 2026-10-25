// Installs a disposable stack and creates the reference data the UI needs.
// Synthetic credentials for a throwaway test instance only.
import { request } from '@playwright/test'

export const ADMIN = { username: 'e2eadmin', password: 'e2e-admin-password', master: 'e2e-master-password' }

export default async function globalSetup(config) {
  const baseURL = config.projects[0].use.baseURL
  const api = await request.newContext({ baseURL })
  const status = await (await api.get('/api/v1/auth/install/status')).json()
  if (!status.installed) {
    const installed = await api.post('/api/v1/auth/install', {
      data: { username: ADMIN.username, password: ADMIN.password, master_password: ADMIN.master,
        generate_master_password: false, email: 'e2e@example.invalid' },
    })
    if (!installed.ok()) throw new Error(`install failed: ${installed.status()} ${await installed.text()}`)
  }
  const login = await api.post('/api/v1/auth/login', {
    form: { username: ADMIN.username, password: ADMIN.password, mpass: ADMIN.master },
  })
  const { access_token: token } = await login.json()
  const headers = { Authorization: `Bearer ${token}` }
  for (const [path, name] of [['/api/v1/clients', 'E2E Client'], ['/api/v1/categories', 'E2E Category']]) {
    const existing = await (await api.get(path, { headers })).json()
    if (!existing.some(item => item.name === name)) {
      const created = await api.post(path, { headers, data: { name } })
      if (!created.ok()) throw new Error(`${path} failed: ${created.status()}`)
    }
  }
  await api.dispose()
}
