import { createApp } from 'vue'
import * as QuasarUI from 'quasar'
import { Quasar, Notify, Loading, Dialog } from 'quasar'
import { createPinia } from 'pinia'
import router from './router'
import App from './App.vue'

// Import Quasar css
import 'quasar/src/css/index.sass'
import '@quasar/extras/material-icons/material-icons.css'
import '@quasar/extras/roboto-font/roboto-font.css'
import '@/css/themes.scss'

const app = createApp(App)
const components = Object.fromEntries(
  Object.entries(QuasarUI).filter(([name]) => name.startsWith('Q'))
)
const directives = {
  ClosePopup: QuasarUI.ClosePopup,
  Ripple: QuasarUI.Ripple
}

app.use(createPinia())
app.use(router)

app.use(Quasar, {
  components,
  directives,
  plugins: {
    Notify,
    Loading,
    Dialog
  },
  config: {
    dark: 'auto',
    notify: {
      position: 'top-right',
      timeout: 3000
    }
  }
})

app.mount('#app')
