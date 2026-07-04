<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from "vue";
import { Check, ChevronDown } from "@lucide/vue";

export interface DesktopSelectOption {
  label: string;
  value: string | number;
}

const props = defineProps<{
  modelValue: string | number;
  options: DesktopSelectOption[];
  ariaLabel?: string;
}>();
const emit = defineEmits<{ "update:modelValue": [value: string | number] }>();

const root = ref<HTMLElement | null>(null);
const optionElements = ref<HTMLElement[]>([]);
const open = ref(false);
const activeIndex = ref(0);
const selectedIndex = computed(() => {
  const index = props.options.findIndex((option) => option.value === props.modelValue);
  return index < 0 ? 0 : index;
});
const selectedLabel = computed(
  () => props.options[selectedIndex.value]?.label ?? String(props.modelValue),
);

function focusActive() {
  void nextTick(() => optionElements.value[activeIndex.value]?.focus());
}

function show() {
  open.value = true;
  activeIndex.value = selectedIndex.value;
  focusActive();
}

function hide() {
  open.value = false;
}

function choose(index: number) {
  const option = props.options[index];
  if (!option) return;
  emit("update:modelValue", option.value);
  hide();
  void nextTick(() => root.value?.querySelector<HTMLElement>("button")?.focus());
}

function move(step: number) {
  const count = props.options.length;
  if (!count) return;
  activeIndex.value = (activeIndex.value + step + count) % count;
  focusActive();
}

function onTriggerKeydown(event: KeyboardEvent) {
  if (["Enter", " ", "ArrowDown", "ArrowUp"].includes(event.key)) {
    event.preventDefault();
    if (!open.value) show();
    if (event.key === "ArrowDown") move(1);
    if (event.key === "ArrowUp") move(-1);
  }
}

function onListKeydown(event: KeyboardEvent) {
  if (event.key === "ArrowDown" || event.key === "ArrowUp") {
    event.preventDefault();
    move(event.key === "ArrowDown" ? 1 : -1);
  } else if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    choose(activeIndex.value);
  } else if (event.key === "Escape" || event.key === "Tab") {
    hide();
  } else if (event.key === "Home" || event.key === "End") {
    event.preventDefault();
    activeIndex.value = event.key === "Home" ? 0 : props.options.length - 1;
    focusActive();
  }
}

function onDocumentPointerDown(event: PointerEvent) {
  if (!root.value?.contains(event.target as Node)) hide();
}

onMounted(() => document.addEventListener("pointerdown", onDocumentPointerDown));
onBeforeUnmount(() => document.removeEventListener("pointerdown", onDocumentPointerDown));
</script>

<template>
  <div ref="root" class="desktop-select" :class="{ open }">
    <button
      type="button"
      class="desktop-select-trigger"
      role="combobox"
      aria-haspopup="listbox"
      :aria-label="ariaLabel"
      :aria-expanded="open"
      @click="open ? hide() : show()"
      @keydown="onTriggerKeydown"
    >
      <span>{{ selectedLabel }}</span>
      <ChevronDown />
    </button>
    <div
      v-if="open"
      class="desktop-select-menu"
      role="listbox"
      :aria-label="ariaLabel"
      @keydown="onListKeydown"
    >
      <button
        v-for="(option, index) in options"
        :key="`${option.value}`"
        :ref="(element) => { if (element) optionElements[index] = element as HTMLElement }"
        type="button"
        role="option"
        :aria-selected="option.value === modelValue"
        :class="{ active: index === activeIndex, selected: option.value === modelValue }"
        @mouseenter="activeIndex = index"
        @click="choose(index)"
      >
        <span>{{ option.label }}</span>
        <Check v-if="option.value === modelValue" />
      </button>
    </div>
  </div>
</template>
