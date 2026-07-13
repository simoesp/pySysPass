import axios from 'axios'
import { useMainStore } from '@/stores'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api/v1',
  timeout: 10000
})

// Request interceptor
api.interceptors.request.use(
  config => {
    const store = useMainStore()
    if (store.token) {
      config.headers.Authorization = `Bearer ${store.token}`
    }
    return config
  },
  error => {
    return Promise.reject(error)
  }
)

// Response interceptor
api.interceptors.response.use(
  response => response,
  error => {
    const requestUrl = String(error.config?.url || '')
    const isAuthLoginRequest =
      requestUrl === '/auth/login' ||
      requestUrl.endsWith('/auth/login')

    if (error.response?.status === 401 && !isAuthLoginRequest) {
      const store = useMainStore()
      store.clearToken()
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

export default api
