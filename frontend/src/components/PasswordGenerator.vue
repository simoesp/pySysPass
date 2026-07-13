<template>
  <q-btn flat round dense icon="casino" color="grey-6" size="sm" title="Generate password">
    <q-menu ref="menu" anchor="bottom right" self="top right" :offset="[0, 6]"
      @before-show="generate" style="width:340px">
      <q-card flat>

        <!-- Generated password display -->
        <q-card-section class="q-pb-xs">
          <div class="row items-center q-gutter-xs">
            <div class="col sp-gen-pwd text-mono q-pa-sm rounded-borders bg-grey-1 ellipsis"
              style="cursor:pointer" :title="generated" @click="copyNow">
              {{ generated || '—' }}
            </div>
            <q-btn flat round dense icon="refresh" color="primary" size="sm" @click.stop="generate" title="Regenerate" />
            <q-btn flat round dense icon="content_copy" color="grey-6" size="sm" @click.stop="copyNow" title="Copy" />
          </div>

          <!-- Strength bar -->
          <div class="q-mt-sm">
            <div class="row items-center justify-between q-mb-xs">
              <span class="text-caption text-grey-6">Strength</span>
              <span class="text-caption text-weight-medium" :class="strengthColor + '--text'">
                {{ strengthLabel }} ({{ Math.round(entropy) }} bits)
              </span>
            </div>
            <q-linear-progress :value="strengthPct" :color="strengthColor" rounded size="6px" />
          </div>
        </q-card-section>

        <q-separator />

        <!-- Controls -->
        <q-card-section class="q-py-sm">
          <!-- Length -->
          <div class="row items-center q-gutter-sm q-mb-sm">
            <span class="text-caption text-grey-7" style="min-width:48px">Length</span>
            <q-slider v-model="length" :min="6" :max="64" :step="1" color="primary" class="col" />
            <q-input v-model.number="length" type="number" min="6" max="64"
              outlined dense style="width:60px" input-class="text-center" />
          </div>

          <!-- Character sets -->
          <div class="row q-col-gutter-xs">
            <div class="col-6"><q-checkbox v-model="useUpper"   label="Uppercase (A–Z)" dense /></div>
            <div class="col-6"><q-checkbox v-model="useLower"   label="Lowercase (a–z)" dense /></div>
            <div class="col-6"><q-checkbox v-model="useDigits"  label="Numbers (0–9)" dense /></div>
            <div class="col-6"><q-checkbox v-model="useSymbols" label="Symbols (!@#…)" dense /></div>
          </div>
          <q-checkbox v-model="noAmbiguous" label="Exclude ambiguous (0 O o I l 1)" dense class="q-mt-xs" />
        </q-card-section>

        <q-separator />

        <q-card-actions align="right" class="q-pa-sm">
          <q-btn flat label="Cancel" dense v-close-popup />
          <q-btn unelevated color="primary" label="Use password" dense no-caps
            :disable="!generated" @click="usePassword" />
        </q-card-actions>

      </q-card>
    </q-menu>
  </q-btn>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { Notify } from 'quasar'

const emit = defineEmits(['use'])

const menu       = ref(null)
const generated  = ref('')
const length     = ref(16)
const useUpper   = ref(true)
const useLower   = ref(true)
const useDigits  = ref(true)
const useSymbols = ref(true)
const noAmbiguous = ref(false)

const UPPER    = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
const LOWER    = 'abcdefghijklmnopqrstuvwxyz'
const DIGITS   = '0123456789'
const SYMBOLS  = '!@#$%^&*()-_=+[]{}|;:,.<>?'
const AMBIGUOUS = new Set([...'0OoIl1'])

function charset() {
  let s = ''
  if (useUpper.value)   s += UPPER
  if (useLower.value)   s += LOWER
  if (useDigits.value)  s += DIGITS
  if (useSymbols.value) s += SYMBOLS
  if (noAmbiguous.value) s = [...s].filter(c => !AMBIGUOUS.has(c)).join('')
  return s || (LOWER + DIGITS)
}

function generate() {
  const chars = charset()
  const len   = Math.max(6, Math.min(64, length.value || 16))
  const buf   = new Uint32Array(len)
  crypto.getRandomValues(buf)
  generated.value = Array.from(buf, n => chars[n % chars.length]).join('')
}

// Re-generate live when options change (while popup is open)
watch([length, useUpper, useLower, useDigits, useSymbols, noAmbiguous], () => {
  if (generated.value) generate()
})

const entropy = computed(() => {
  const size = charset().length
  return size < 2 ? 0 : length.value * Math.log2(size)
})

const strengthPct   = computed(() => Math.min(1, entropy.value / 100))
const strengthLabel = computed(() => {
  const e = entropy.value
  if (e < 40) return 'Weak'
  if (e < 60) return 'Fair'
  if (e < 80) return 'Good'
  return 'Excellent'
})
const strengthColor = computed(() => {
  const e = entropy.value
  if (e < 40) return 'negative'
  if (e < 60) return 'warning'
  if (e < 80) return 'positive'
  return 'teal'
})

async function copyNow() {
  if (!generated.value) return
  try {
    await navigator.clipboard.writeText(generated.value)
    Notify.create({ message: 'Password copied', color: 'positive', timeout: 1200 })
  } catch {
    Notify.create({ message: 'Copy failed', color: 'negative' })
  }
}

function usePassword() {
  emit('use', generated.value)
  menu.value?.hide()
}
</script>

<style scoped>
.sp-gen-pwd {
  font-family: 'Courier New', Courier, monospace;
  font-size: 13px;
  letter-spacing: 0.04em;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
