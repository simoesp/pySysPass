import { defineConfig, devices } from '@playwright/test'

// Runs against an already running stack, e.g. scripts/e2e-stack.sh.
export default defineConfig({
  testDir: './tests',
  globalSetup: './global-setup.js',
  fullyParallel: false,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: process.env.E2E_BASE_URL || 'http://127.0.0.1:18300',
    trace: 'retain-on-failure',
    permissions: ['clipboard-read', 'clipboard-write'],
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
