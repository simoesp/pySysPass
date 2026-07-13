import { setCssVar, Dark } from 'quasar'
import { themes, defaultTheme } from '@/themes/index'

const STORAGE_KEY = 'sp_theme'

export function applyTheme(themeId) {
  const theme = themes.find(t => t.id === themeId) ?? themes.find(t => t.id === defaultTheme)
  const root = document.documentElement
  root.style.setProperty('--sp-header-bg', theme.headerBg)
  root.style.setProperty('--sp-sidebar-bg', theme.sidebarBg)
  root.style.setProperty('--sp-accent-color', theme.accentColor)
  root.style.setProperty('--sp-content-bg', theme.contentBg)
  root.style.setProperty('--sp-card-bg', theme.cardBg)
  root.style.setProperty('--sp-card-bg-alt', theme.cardBgAlt)
  root.style.setProperty('--sp-text-primary', theme.textPrimary)
  root.style.setProperty('--sp-text-secondary', theme.textSecondary)
  root.style.setProperty('--sp-border-color', theme.borderColor)
  setCssVar('primary', theme.primary)
  Dark.set(theme.dark === true)
  localStorage.setItem(STORAGE_KEY, themeId)
}

export function getSavedTheme() {
  return localStorage.getItem(STORAGE_KEY) ?? defaultTheme
}

export { themes }
