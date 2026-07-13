import { defineStore } from 'pinia'

export const useMainStore = defineStore('main', {
  state: () => ({
    user: null,
    token: localStorage.getItem('auth_token') || null,
    sidebar: true,
    darkMode: false
  }),
  
  getters: {
    isAuthenticated: (state) => !!state.token,
    currentUser: (state) => state.user,
    isAdmin: (state) => state.user?.is_admin ?? false,
    // Returns true when the user is an admin OR their profile explicitly grants the permission key.
    hasPermission: (state) => (key) => {
      if (state.user?.is_admin) return true
      return state.user?.permissions?.[key] ?? false
    },
  },
  
  actions: {
    setToken(token) {
      this.token = token
      localStorage.setItem('auth_token', token)
    },
    
    clearToken() {
      this.token = null
      this.user = null
      localStorage.removeItem('auth_token')
    },
    
    setUser(user) {
      this.user = user
    },
    
    toggleSidebar() {
      this.sidebar = !this.sidebar
    },
    
    toggleDarkMode() {
      this.darkMode = !this.darkMode
    }
  }
})
