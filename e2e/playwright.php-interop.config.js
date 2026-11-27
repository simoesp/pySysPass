import { defineConfig, devices } from '@playwright/test'

// PHP <-> pySysPass interoperability through the real sysPass web UI.
// Start the stack first: scripts/php-interop-stack.sh up
export default defineConfig({
  testDir: './php-interop',
  retries: 0,
  reporter: [['list']],
  use: { trace: 'retain-on-failure' },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
