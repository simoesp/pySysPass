import { test, expect } from '@playwright/test'
import { ADMIN } from '../global-setup.js'

async function signIn(page, password = ADMIN.password) {
  await page.goto('/login')
  await page.getByPlaceholder('Enter your username').fill(ADMIN.username)
  await page.getByPlaceholder('Enter your password').fill(password)
  await page.getByRole('button', { name: /sign in|unlock vault/i }).click()
}

async function pickOption(page, label, option) {
  await page.getByLabel(label).click()
  await page.getByRole('option', { name: option }).click()
}

test('sign-in, create an account, reveal its password, sign out', async ({ page, request }) => {
  await signIn(page)
  await expect(page.getByRole('button', { name: 'New account' }).first()).toBeVisible()
  const token = await page.evaluate(() => localStorage.getItem('auth_token'))
  expect(token).toBeTruthy()

  const title = `E2E account ${Date.now()}`
  await page.getByRole('button', { name: 'New account' }).first().click()
  await page.getByLabel('Name *').fill(title)
  await page.getByLabel('Password *').fill('Browser-秘密-Secret!')
  await pickOption(page, 'Category *', 'E2E Category')
  await pickOption(page, 'Client *', 'E2E Client')
  await page.getByRole('button', { name: 'Create' }).click()
  await expect(page.getByText('Account created')).toBeVisible()

  const card = page.locator('.sp-card', { hasText: title })
  await expect(card).toBeVisible()
  // Quasar renders the Material icon name as the <i> element's text.
  await card.locator('button').filter({ has: page.locator('i', { hasText: /^content_copy$/ }) }).click()
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe('Browser-秘密-Secret!')

  await page.locator('.q-btn-dropdown').first().click()
  await page.getByText('Sign out').click()
  await expect(page).toHaveURL(/\/login/)
  // Server-side revocation: the copied bearer no longer works.
  const reused = await request.get('/api/v1/auth/me', { headers: { Authorization: `Bearer ${token}` } })
  expect(reused.status()).toBe(401)
})

test('wrong password is refused and protected pages need sign-in', async ({ page }) => {
  await page.goto('/accounts')
  await expect(page).toHaveURL(/\/login/)
  await signIn(page, 'not-the-password')
  await expect(page.getByText(/incorrect username or password/i)).toBeVisible()
  await expect(page).toHaveURL(/\/login/)
})

test('pages carry the security headers', async ({ request }) => {
  for (const path of ['/', '/login', '/accounts']) {
    const response = await request.get(path)
    expect(response.headers()['content-security-policy']).toContain("frame-ancestors 'none'")
    expect(response.headers()['x-frame-options']).toBe('DENY')
  }
})
