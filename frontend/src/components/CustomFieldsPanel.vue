<template>
  <div v-if="defs.length || loadError" class="q-mt-sm">
    <div class="text-subtitle2 text-weight-bold q-mb-sm text-grey-7">Custom Fields</div>

    <q-banner v-if="loadError" dense rounded class="bg-negative text-white q-mb-sm" icon="error">
      Failed to load custom fields
    </q-banner>

    <div class="q-gutter-y-sm">
      <div v-for="def in defs" :key="def.id">
        <q-input
          v-model="localValues[def.id]"
          :label="def.name + (def.is_required ? ' *' : '')"
          :type="inputType(def.type_name)"
          :hint="def.help || undefined"
          :required="def.is_required"
          :readonly="def.is_encrypted"
          outlined dense
          :bg-color="def.is_encrypted ? 'grey-2' : undefined"
        >
          <template v-if="def.is_encrypted" v-slot:append>
            <q-icon name="lock" color="warning" size="18px">
              <q-tooltip>Encrypted — edit in sysPass PHP</q-tooltip>
            </q-icon>
          </template>
        </q-input>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, watch, onMounted } from 'vue'
import api from '@/api/axios'

const props = defineProps({
  moduleId: { type: Number, required: true },
  itemId:   { type: Number, default: null },
})

const emit = defineEmits(['ready'])

const defs        = ref([])
const serverValues = ref({})
const localValues  = ref({})
const loadError    = ref(false)

const TYPE_INPUT = {
  password: 'password', email: 'email', url: 'url',
  number: 'number', date: 'date',
}
function inputType(typeName) { return TYPE_INPUT[typeName] ?? 'text' }

async function load() {
  loadError.value = false
  try {
    const defsRes = await api.get('/custom-fields/definitions', { params: { module_id: props.moduleId } })
    defs.value = defsRes.data

    if (props.itemId) {
      const valsRes = await api.get(`/custom-fields/values/${props.moduleId}/${props.itemId}`)
      const map = {}
      for (const v of valsRes.data) map[v.def_id] = v.value ?? ''
      serverValues.value = map
    }

    const init = {}
    for (const d of defs.value) init[d.id] = serverValues.value[d.id] ?? ''
    localValues.value = init
  } catch (err) {
    console.error('[CustomFieldsPanel] load failed (module=%d, item=%s):', props.moduleId, props.itemId, err)
    loadError.value = true
  }
  emit('ready')
}

async function save(itemId) {
  const id = itemId ?? props.itemId
  if (!id || !defs.value.length) return
  const saves = []
  for (const [defId, val] of Object.entries(localValues.value)) {
    const v = (val ?? '').toString().trim()
    const prev = serverValues.value[defId] ?? ''
    if (v === prev) continue
    if (v === '') {
      saves.push(api.delete(`/custom-fields/values/${defId}/${props.moduleId}/${id}`).catch(() => {}))
    } else {
      saves.push(api.post('/custom-fields/values', {
        def_id: Number(defId), module_id: props.moduleId, item_id: id, value: v,
      }).catch(() => {}))
    }
  }
  if (saves.length) await Promise.all(saves)
  if (id) {
    try {
      const valsRes = await api.get(`/custom-fields/values/${props.moduleId}/${id}`)
      const map = {}
      for (const v of valsRes.data) map[v.def_id] = v.value ?? ''
      serverValues.value = map
    } catch { /* non-fatal */ }
  }
}

watch(() => props.itemId, () => { if (props.itemId) load() })
onMounted(load)

defineExpose({ save, load })
</script>
