import { defineStore } from "pinia";
import type { AppSettings, Dashboard, Incident } from "../types";

export const useAppStore = defineStore("app", {
  state: () => ({
    dashboard: {
      monitoring: false,
      uptime_seconds: 0,
      storage_bytes: 0,
      incident_storage_bytes: 0,
      storage_limit_bytes: 2_147_483_648,
      etw_status: "正在检查能力",
      wpr_status: "正在检查能力",
      cpu_percent: 0,
      memory_percent: 0,
      disk_latency_ms: 0,
      network_kbps: 0,
      last_sample_at: null,
      data_path: "",
      sensitivity_level_max: 0,
      blackbox_cpu_percent: 0,
      blackbox_memory_bytes: 0,
      blackbox_disk_write_kbps: 0,
      effective_interval_seconds: 0,
      shortcut_status: "正在注册",
    } as Dashboard,
    incidents: [] as Incident[],
    settings: {
      sample_interval_seconds: 2,
      retention_days: 30,
      rolling_limit_gb: 2,
      incident_limit_gb: 20,
      ai_mode: "disabled",
      ollama_endpoint: "http://127.0.0.1:11434",
      ollama_model: "qwen3:8b",
      dumps_enabled: false,
      auto_trigger_enabled: false,
      auto_trigger_cooldown_minutes: 15,
      auto_trigger_max_per_hour: 4,
    } as AppSettings,
  }),
});
