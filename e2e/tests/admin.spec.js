import { readFile } from 'node:fs/promises'
import { test, expect } from '@playwright/test'
import { ADMIN } from '../global-setup.js'

async function signIn(page, username = ADMIN.username, password = ADMIN.password) {
  await page.goto('/login')
  await page.getByPlaceholder('Enter your username').fill(username)
  await page.getByPlaceholder('Enter your password').fill(password)
  await page.getByRole('button', { name: /sign in|unlock vault/i }).click()
}

async function signOut(page) {
  await page.locator('.q-btn-dropdown').first().click()
  await page.getByText('Sign out').click()
  await expect(page).toHaveURL(/\/login/)
}

async function apiHeaders(page) {
  return { Authorization: `Bearer ${await page.evaluate(() => localStorage.getItem('auth_token'))}` }
}

async function pickOption(page, label, option) {
  await page.getByLabel(label).click()
  await page.getByRole('option', { name: option, exact: true }).click()  // single select: the menu closes
}

async function settingsTab(page, name) {
  await page.goto('/settings')
  await page.getByRole('tab', { name: new RegExp(`^([a-z_]+\\s*)?${name}$`) }).click()
}

test('admin creates a profile, group and user; the user gets only those rights', async ({ page, request }) => {
  const stamp = Date.now()
  const names = { profile: `E2E viewer ${stamp}`, group: `E2E group ${stamp}`, user: `e2euser${stamp}` }
  await signIn(page)
  await expect(page.getByRole('button', { name: 'New account' }).first()).toBeVisible()

  await page.goto('/user-profiles')
  await page.getByRole('button', { name: 'New Profile' }).click()
  await page.getByLabel('Name *').fill(names.profile)
  await page.getByRole('switch', { name: 'View accounts', exact: true }).click()
  await page.getByRole('switch', { name: 'View passwords', exact: true }).click()
  await page.getByRole('button', { name: 'Create' }).click()
  await expect(page.getByText('Profile created')).toBeVisible()

  await page.goto('/user-groups')
  await page.getByRole('button', { name: 'New Group' }).click()
  await page.getByLabel('Name *').fill(names.group)
  await page.getByRole('button', { name: 'Create' }).click()
  await expect(page.getByText('Group created')).toBeVisible()

  await page.goto('/users')
  await page.getByRole('button', { name: 'New User' }).click()
  await page.getByLabel('Username *').fill(names.user)
  await page.getByLabel('Full Name').fill('E2E User')
  await pickOption(page, 'User Profile', names.profile)
  await pickOption(page, 'Primary Group *', names.group)
  await page.getByLabel('Password *').fill('e2e-user-password')
  await page.getByRole('button', { name: 'Create' }).click()
  await expect(page.getByText('User created')).toBeVisible()
  await expect(page.getByRole('cell', { name: names.user, exact: true })).toBeVisible()

  await signOut(page)
  await signIn(page, names.user, 'e2e-user-password')
  // First sign-in of a new user: unlock with the vault's master password, as in PHP.
  const master = page.getByPlaceholder('Enter your master password')
  await expect(master).toBeVisible()
  await master.fill(ADMIN.master)
  await page.getByRole('button', { name: /unlock vault/i }).click()
  await expect(page).toHaveURL(/\/accounts/)
  const headers = await apiHeaders(page)
  expect(await (await request.get('/api/v1/auth/me', { headers })).json()).toMatchObject({ username: names.user })
  expect((await request.get('/api/v1/accounts', { headers })).status()).toBe(200)
  for (const path of ['/api/v1/users', '/api/v1/settings/general', '/api/v1/backup/']) {
    expect((await request.get(path, { headers })).status(), path).toBe(403)
  }
  await signOut(page)
})

test('admin exports XML and imports CSV from Settings; imports belong to the admin', async ({ page, request }) => {
  await signIn(page)
  await expect(page.getByRole('button', { name: 'New account' }).first()).toBeVisible()
  const headers = await apiHeaders(page)
  const me = await (await request.get('/api/v1/auth/me', { headers })).json()

  const title = `E2E imported ${Date.now()}`
  await settingsTab(page, 'Import Accounts')
  await page.getByLabel('Import format').click()
  await page.getByRole('option', { name: 'csv', exact: true }).click()
  await page.locator('input[type=file]').setInputFiles({
    name: 'accounts.csv', mimeType: 'text/csv',
    buffer: Buffer.from(`name,client,category,login,password\n${title},E2E Client,E2E Category,imp,Imported-Secret-1\n`),
  })
  await page.getByRole('button', { name: 'Import', exact: true }).click()
  await expect(page.getByText('Import completed')).toBeVisible()
  await expect(page.getByText('Imported: 1 accounts (0 skipped, 0 failed)')).toBeVisible()

  const found = await (await request.get('/api/v1/accounts', { headers, params: { q: title } })).json()
  expect(found).toHaveLength(1)
  expect(found[0].user_id).toBe(me.id)  // the signed-in admin, not a fixed user id
  const secret = await (await request.get(`/api/v1/accounts/${found[0].id}/password`, { headers })).json()
  expect(secret.password).toBe('Imported-Secret-1')

  await settingsTab(page, 'Backup')
  const downloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export as XML' }).click()
  const download = await downloadPromise
  expect(download.suggestedFilename()).toMatch(/\.xml$/)
  const xml = await readFile(await download.path(), 'utf8')
  expect(xml).toContain('<Root>')
  expect(xml).toContain(title)
  expect(xml).not.toContain('Imported-Secret-1')  // passwords stay Defuse ciphertext
})

test('admin creates and downloads a full backup', async ({ page }) => {
  await signIn(page)
  await expect(page.getByRole('button', { name: 'New account' }).first()).toBeVisible()
  await page.goto('/backup')
  await page.getByRole('button', { name: 'Create Backup' }).click()
  const created = page.getByText(/^Backup created: /)
  await expect(created).toBeVisible({ timeout: 60_000 })
  const filename = (await created.textContent()).replace('Backup created: ', '').trim()
  const row = page.getByRole('row').filter({ hasText: filename })
  await expect(row).toBeVisible()
  const downloadPromise = page.waitForEvent('download')
  await row.locator('button').filter({ has: page.locator('i', { hasText: /^download$/ }) }).click()
  const download = await downloadPromise
  const archive = await readFile(await download.path())
  expect(archive.subarray(0, 2).toString()).toBe('PK')  // a ZIP archive
  expect(archive.length).toBeGreaterThan(1000)  // includes the database dump
})
