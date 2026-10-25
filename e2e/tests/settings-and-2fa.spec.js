import { createHmac } from 'node:crypto'
import { test, expect } from '@playwright/test'
import { ADMIN } from '../global-setup.js'

// RFC 6238 TOTP (SHA-1, 6 digits, 30 s), as authenticator apps compute it.
function totp(secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const char of secret.replace(/=+$/, '').toUpperCase()) {
    bits += alphabet.indexOf(char).toString(2).padStart(5, '0')
  }
  const key = Buffer.from(bits.match(/.{8}/g).map(byte => parseInt(byte, 2)))
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)))
  const hmac = createHmac('sha1', key).update(counter).digest()
  const offset = hmac[hmac.length - 1] & 0xf
  return String((hmac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}

async function signIn(page) {
  await page.goto('/login')
  await page.getByPlaceholder('Enter your username').fill(ADMIN.username)
  await page.getByPlaceholder('Enter your password').fill(ADMIN.password)
  await page.getByRole('button', { name: /sign in|unlock vault/i }).click()
}

async function apiHeaders(page) {
  return { Authorization: `Bearer ${await page.evaluate(() => localStorage.getItem('auth_token'))}` }
}

test('settings: "Show password as image" turns the reveal into an image', async ({ page, request }) => {
  await signIn(page)
  await expect(page.getByRole('button', { name: 'New account' }).first()).toBeVisible()
  const headers = await apiHeaders(page)
  const [clients, categories] = await Promise.all(
    ['/api/v1/clients', '/api/v1/categories'].map(async path => (await request.get(path, { headers })).json()))
  const created = await request.post('/api/v1/accounts', {
    headers,
    data: { title: `E2E image ${Date.now()}`, password: 'Image-Secret-42', is_public: true,
      client_id: clients.find(c => c.name === 'E2E Client').id,
      category_id: categories.find(c => c.name === 'E2E Category').id },
  })
  expect(created.ok()).toBeTruthy()
  const accountId = (await created.json()).id

  await page.goto('/settings')
  await page.getByRole('tab', { name: /^(manage_accounts\s*)?Accounts$/ }).click()
  const toggle = page.getByRole('switch', { name: 'Show password as image', exact: true })
  if ((await toggle.getAttribute('aria-checked')) !== 'true') await toggle.click()
  await page.getByRole('button', { name: 'Save Account Settings' }).click()
  await expect(page.getByText('Account settings saved')).toBeVisible()

  try {
    await page.goto(`/accounts/${accountId}`)
    await page.locator('.sp-field-card--password button').filter({ has: page.locator('i', { hasText: /^visibility$/ }) }).click()
    const image = page.locator('.sp-field-card--password img[alt="Password"]')
    await expect(image).toBeVisible()
    expect(await image.getAttribute('src')).toMatch(/^data:image\/png;base64,/)
    await expect(page.locator('.sp-field-card--password')).not.toContainText('Image-Secret-42')
    // Copy still yields the text, as sysPass PHP copyPass does.
    await page.locator('.sp-field-card--password button').filter({ has: page.locator('i', { hasText: /^content_copy$/ }) }).click()
    await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe('Image-Secret-42')
  } finally {
    const settings = await (await request.get('/api/v1/settings/accounts', { headers })).json()
    await request.put('/api/v1/settings/accounts', { headers, data: { ...settings, account_pass_to_image: false } })
  }
})

test('2FA: enable in settings, enroll in the profile, sign in with a code', async ({ page, request }) => {
  await signIn(page)
  await expect(page.getByRole('button', { name: 'New account' }).first()).toBeVisible()

  await page.goto('/settings')
  await page.getByRole('tab', { name: /^(verified_user\s*)?Security$/ }).click()
  await page.getByRole('radio', { name: /^Enabled/ }).click()
  await page.getByRole('button', { name: 'Save Security Settings' }).click()
  await expect(page.getByText('Security settings saved')).toBeVisible()

  await page.goto('/profile')
  await page.getByRole('button', { name: 'Set up 2FA' }).click()
  await page.getByLabel('Password', { exact: true }).fill(ADMIN.password)
  await page.getByRole('button', { name: 'Continue' }).click()
  const secret = await page.getByLabel('Secret (manual entry)').inputValue()
  expect(secret).toMatch(/^[A-Z2-7]+=*$/)
  await page.getByLabel('6-digit code').fill(totp(secret))
  await page.getByRole('button', { name: 'Verify and enable' }).click()
  await expect(page.getByRole('button', { name: 'Copy codes' })).toBeVisible()
  await page.getByRole('button', { name: 'Done' }).click()

  try {
    await page.locator('.q-btn-dropdown').first().click()
    await page.getByText('Sign out').click()
    await expect(page).toHaveURL(/\/login/)

    await signIn(page)
    const otp = page.getByPlaceholder('6-digit code or backup code')
    await expect(otp).toBeVisible()
    await otp.fill('000000')
    await page.getByRole('button', { name: /unlock vault/i }).click()
    await expect(page).toHaveURL(/\/login/)  // a wrong code does not sign in
    await otp.fill(totp(secret))
    await page.getByRole('button', { name: /unlock vault/i }).click()
    await expect(page.getByRole('button', { name: 'New account' }).first()).toBeVisible()
  } finally {
    // Leave the disposable instance as the other tests expect it.
    const headers = await apiHeaders(page)
    await request.post('/api/v1/2fa/disable', { headers, data: { password: ADMIN.password } })
    await request.put('/api/v1/settings/two-factor', { headers, data: { mode: 'disabled' } })
  }
})
