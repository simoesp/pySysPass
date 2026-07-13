<template>
  <div v-if="password" class="q-mt-xs">
    <div class="row items-center justify-between q-mb-xs">
      <span class="text-caption text-grey-6">Strength</span>
      <span class="text-caption text-weight-medium" :class="`${strength.color}--text`">
        {{ strength.label }} ({{ Math.round(strength.entropy) }} bits)
      </span>
    </div>
    <q-linear-progress :value="strength.percentage" :color="strength.color" rounded size="6px" />
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  password: {
    type: String,
    default: '',
  },
})

const strength = computed(() => {
  let poolSize = 0
  if (/[a-z]/.test(props.password)) poolSize += 26
  if (/[A-Z]/.test(props.password)) poolSize += 26
  if (/\d/.test(props.password)) poolSize += 10
  if (/[^a-zA-Z\d]/.test(props.password)) poolSize += 32

  const entropy = poolSize > 1 ? props.password.length * Math.log2(poolSize) : 0
  if (entropy < 40) return { entropy, percentage: entropy / 100, label: 'Weak', color: 'negative' }
  if (entropy < 60) return { entropy, percentage: entropy / 100, label: 'Fair', color: 'warning' }
  if (entropy < 80) return { entropy, percentage: entropy / 100, label: 'Good', color: 'positive' }
  return { entropy, percentage: Math.min(1, entropy / 100), label: 'Excellent', color: 'teal' }
})
</script>
