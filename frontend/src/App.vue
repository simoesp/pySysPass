<template>
  <router-view />
</template>

<script setup>
import { onMounted } from 'vue'
import { applyTheme, getSavedTheme } from '@/composables/useTheme'

onMounted(() => {
  applyTheme(getSavedTheme())
})
</script>

<style>
#app {
  font-family: 'Roboto', sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}
</style>
