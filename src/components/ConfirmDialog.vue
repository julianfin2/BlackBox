<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { Trash2, TriangleAlert, X } from "@lucide/vue";

const props = withDefaults(
  defineProps<{
    open: boolean;
    title: string;
    description: string;
    confirmLabel?: string;
    busy?: boolean;
  }>(),
  { confirmLabel: "确认", busy: false },
);
const emit = defineEmits<{ cancel: []; confirm: [] }>();
const cancelButton = ref<HTMLButtonElement | null>(null);

function cancel() {
  if (!props.busy) emit("cancel");
}

function onKeydown(event: KeyboardEvent) {
  if (props.open && event.key === "Escape") {
    event.preventDefault();
    cancel();
  }
}

watch(
  () => props.open,
  (open) => {
    if (open) void nextTick(() => cancelButton.value?.focus());
  },
);
onMounted(() => document.addEventListener("keydown", onKeydown));
onBeforeUnmount(() => document.removeEventListener("keydown", onKeydown));
</script>

<template>
  <div v-if="open" class="confirm-backdrop" @click.self="cancel">
    <section
      class="confirm-dialog"
      role="alertdialog"
      aria-modal="true"
      :aria-labelledby="`${$attrs.id || 'confirm'}-title`"
      :aria-describedby="`${$attrs.id || 'confirm'}-description`"
    >
      <header>
        <span><TriangleAlert /></span>
        <div>
          <h2 :id="`${$attrs.id || 'confirm'}-title`">{{ title }}</h2>
          <p :id="`${$attrs.id || 'confirm'}-description`">{{ description }}</p>
        </div>
        <button type="button" class="icon" aria-label="关闭" :disabled="busy" @click="cancel">
          <X />
        </button>
      </header>
      <footer>
        <button ref="cancelButton" type="button" class="secondary" :disabled="busy" @click="cancel">
          取消
        </button>
        <button type="button" class="confirm-danger" :disabled="busy" @click="emit('confirm')">
          <Trash2 />
          {{ busy ? "正在删除…" : confirmLabel }}
        </button>
      </footer>
    </section>
  </div>
</template>
