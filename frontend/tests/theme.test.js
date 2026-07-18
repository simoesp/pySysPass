import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('quasar', () => ({
  setCssVar: vi.fn(),
  Dark: { set: vi.fn() },
}))

import { setCssVar, Dark } from 'quasar'
import { applyTheme, getSavedTheme, themes } from '@/composables/useTheme'
import { defaultTheme } from '@/themes/index'

describe('theme composable', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
  })

  it('applies a known theme and persists the choice', () => {
    const theme = themes[0]
    applyTheme(theme.id)
    expect(localStorage.getItem('sp_theme')).toBe(theme.id)
    expect(setCssVar).toHaveBeenCalledWith('primary', theme.primary)
    expect(Dark.set).toHaveBeenCalledWith(theme.dark === true)
    expect(
      document.documentElement.style.getPropertyValue('--sp-header-bg')
    ).toBe(theme.headerBg)
  })

  it('falls back to the default theme for unknown ids', () => {
    applyTheme('does-not-exist')
    const fallback = themes.find(t => t.id === defaultTheme)
    expect(setCssVar).toHaveBeenCalledWith('primary', fallback.primary)
  })

  it('getSavedTheme returns default when nothing stored', () => {
    expect(getSavedTheme()).toBe(defaultTheme)
    localStorage.setItem('sp_theme', 'something')
    expect(getSavedTheme()).toBe('something')
  })
})
