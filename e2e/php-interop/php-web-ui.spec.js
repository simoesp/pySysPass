// R5 / #56: the sysPass PHP web UI reads what pySysPass writes, and
// pySysPass unlocks the vault of a PHP-created installation.
// Requires scripts/php-interop-stack.sh up. Synthetic credentials only.
import { test, expect } from '@playwright/test'

const PHP = 'http://127.0.0.1:18400'
const PY = 'http://127.0.0.1:18401/api/v1'
const SECRET = 'Py-Written-秘密-2026!'

test('PHP shows passwords and public links written by pySysPass', async ({ page, request }) => {
  // pySysPass signs in with the PHP-created admin (PHP-authored mPass/mKey).
  const login = await request.post(`${PY}/auth/login`, {
    form: { username: 'phpadmin', password: 'PhpAdmin-Pass-2026' },
  })
  expect(login.status()).toBe(200)
  const headers = { Authorization: `Bearer ${(await login.json()).access_token}` }
  const stamp = Date.now()
  const client = await (await request.post(`${PY}/clients`, { headers, data: { name: `Py Client ${stamp}` } })).json()
  const category = await (await request.post(`${PY}/categories`, { headers, data: { name: `Py Category ${stamp}` } })).json()
  const title = `Written by pySysPass ${stamp}`
  const created = await request.post(`${PY}/accounts`, {
    headers,
    data: { title, login: 'py-user', password: SECRET, url: 'https://py.example', client_id: client.id,
      category_id: category.id, is_public: true },
  })
  expect(created.status()).toBe(201)
  const account = await created.json()
  const settings = await (await request.get(`${PY}/settings/accounts`, { headers })).json()
  expect((await request.put(`${PY}/settings/accounts`, {
    headers, data: { ...settings, publinks_enabled: true, publinks_max_views: 5, publinks_max_time: 3600 },
  })).status()).toBe(200)
  const link = await request.post(`${PY}/accounts/${account.id}/public-links`, { headers, data: { account_id: account.id } })
  expect(link.status()).toBe(201)

  // PHP AccountController::viewLinkAction renders the native Vault snapshot.
  await page.goto(`${PHP}/index.php?r=account/viewLink/${(await link.json()).hash}`)
  // PHP renders the snapshot in read-only inputs.
  await expect(page.getByRole('textbox', { name: 'Account name' })).toHaveValue(title)
  expect(await page.content()).toContain(SECRET)

  // PHP's own login, search, and "view password" dialog decrypt the account.
  await page.goto(`${PHP}/index.php`)
  await page.fill('#user', 'phpadmin')
  await page.fill('#pass', 'PhpAdmin-Pass-2026')
  await page.click('#btnLogin')
  await page.waitForURL(/r=index/)
  const viewPass = page.waitForResponse(response => response.url().includes('viewPass'))
  await page.locator(`[data-action-route="account/viewPass"][data-item-id="${account.id}"]`).first().click()
  const dialog = await viewPass
  expect(dialog.status()).toBe(200)
  expect((await dialog.json()).status).toBe(0)
  await expect.poll(async () => (await page.content()).includes(SECRET)).toBe(true)
})

test('PHP imports a password-protected XML export written by pySysPass', async ({ page, request }) => {
  const login = await request.post(`${PY}/auth/login`, {
    form: { username: 'phpadmin', password: 'PhpAdmin-Pass-2026' },
  })
  const headers = { Authorization: `Bearer ${(await login.json()).access_token}` }
  const stamp = Date.now()
  const client = await (await request.post(`${PY}/clients`, { headers, data: { name: `Export Client ${stamp}` } })).json()
  const category = await (await request.post(`${PY}/categories`, { headers, data: { name: `Export Category ${stamp}` } })).json()
  const title = `Exported by pySysPass ${stamp}`
  const secret = `Export-秘密-${stamp}`
  const account = await (await request.post(`${PY}/accounts`, {
    headers,
    data: { title, login: 'export-user', password: secret, client_id: client.id, category_id: category.id, is_public: true },
  })).json()

  const exported = await request.post(`${PY}/import-export/export/xml/protected`, {
    headers,
    form: { export_password: 'Export-File-Pass-2026', master_password: 'Php-Master-Pass-2026', account_ids: String(account.id) },
  })
  expect(exported.status()).toBe(200)
  const xml = (await exported.json()).content
  // Only the export holds the account now.
  expect((await request.delete(`${PY}/accounts/${account.id}`, { headers })).status()).toBe(204)

  await page.goto(`${PHP}/index.php`)
  await page.fill('#user', 'phpadmin')
  await page.fill('#pass', 'PhpAdmin-Pass-2026')
  await page.click('#btnLogin')
  await page.waitForURL(/r=index/)
  // The config view loads through sysPass's menu, which also wires the uploader.
  await page.locator('[data-route="configManager/index"]').first().click()
  await expect(page.locator('#importPwd')).toBeAttached()
  // Open whichever tab holds the import form.
  const tab = await page.locator('#importPwd').evaluate(input => input.closest('[id^="tabs-"]').id)
  await page.locator(`a[href="#${tab}"]`).click()
  await page.fill('#importPwd', 'Export-File-Pass-2026')
  await page.fill('#importMasterPwd', 'Php-Master-Pass-2026')
  const imported = page.waitForResponse(response => response.url().includes('configImport/import'))
  await page.setInputFiles('#inFile', { name: 'pysyspass-export.xml', mimeType: 'text/xml', buffer: Buffer.from(xml) })
  const importResult = await (await imported).json()
  expect(importResult.status, JSON.stringify(importResult)).toBe(0)

  // The imported account is a PHP row now; PHP's own dialog decrypts it.
  await page.goto(`${PHP}/index.php?r=index`)
  const search = await request.get(`${PY}/accounts/search`, { headers, params: { q: title } })
  const [copy] = await search.json()
  expect(copy && copy.title).toBe(title)
  const viewPass = page.waitForResponse(response => response.url().includes('viewPass'))
  await page.locator(`[data-action-route="account/viewPass"][data-item-id="${copy.id}"]`).first().click()
  expect((await (await viewPass).json()).status).toBe(0)
  await expect.poll(async () => (await page.content()).includes(secret)).toBe(true)
})
