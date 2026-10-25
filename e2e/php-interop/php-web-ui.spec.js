// R5 / #56: the sysPass PHP web UI reads what pySysPass writes, and
// pySysPass unlocks the vault of a PHP-created installation.
// Requires scripts/php-interop-stack.sh up. Synthetic credentials only.
import { createHmac } from 'node:crypto'
import { test, expect } from '@playwright/test'

// RFC 6238 TOTP (SHA-1, 30 s, 6 digits) for a Base32 seed.
function totp(seed) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const char of seed.replace(/=+$/, '').toUpperCase()) bits += alphabet.indexOf(char).toString(2).padStart(5, '0')
  const key = Buffer.from(bits.match(/.{8}/g).map(byte => parseInt(byte, 2)))
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)))
  const digest = createHmac('sha1', key).update(counter).digest()
  const offset = digest[digest.length - 1] & 0xf
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, '0')
}

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

// Needs the stack started with AUTHENTICATOR_DIR (sysPass/plugin-Authenticator).
test('the PHP Authenticator plugin enforces 2FA enrolled through pySysPass', async ({ page, request }) => {
  test.skip(!process.env.INTEROP_2FA, 'start the stack with AUTHENTICATOR_DIR and set INTEROP_2FA=1')
  const login = await request.post(`${PY}/auth/login`, {
    form: { username: 'phpadmin', password: 'PhpAdmin-Pass-2026' },
  })
  let headers = { Authorization: `Bearer ${(await login.json()).access_token}` }
  expect((await request.put(`${PY}/settings/two-factor`, { headers, data: { mode: 'enabled' } })).status()).toBe(200)
  const setup = await (await request.post(`${PY}/2fa/setup`, { headers, data: { password: 'PhpAdmin-Pass-2026' } })).json()
  const enabled = await request.post(`${PY}/2fa/enable`, { headers, data: { code: totp(setup.secret) } })
  expect(enabled.status()).toBe(200)
  const { access_token: rotated, backup_codes: codes } = await enabled.json()
  headers = { Authorization: `Bearer ${rotated}` }

  async function phpSignIn(pin) {
    await page.goto(`${PHP}/index.php`)
    await page.fill('#user', 'phpadmin')
    await page.fill('#pass', 'PhpAdmin-Pass-2026')
    await page.click('#btnLogin')
    await page.waitForURL(/authenticatorLogin/)
    await page.fill('#pin', pin)
    const checked = page.waitForResponse(response => response.url().includes('checkCode'))
    await page.click('#btnLogin')
    return (await (await checked).json()).status
  }

  try {
    // PHP reads the AuthenticatorData pySysPass wrote and demands a code.
    expect(await phpSignIn('000000')).not.toBe(0)
    expect(await phpSignIn(totp(setup.secret))).toBe(0)
    await page.context().clearCookies()
    // A pySysPass recovery code is a valid PHP recovery code (20 hex chars).
    expect(await phpSignIn(codes[0])).toBe(0)
  } finally {
    await request.post(`${PY}/2fa/disable`, { headers, data: { password: 'PhpAdmin-Pass-2026' } })
  }
})
