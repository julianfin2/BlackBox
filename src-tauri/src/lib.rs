mod ai;
mod analysis;
mod capabilities;
mod collector;
mod storage;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager, State, WindowEvent,
};
use tauri_plugin_global_shortcut::{GlobalShortcutExt, ShortcutState};
use uuid::Uuid;

const INCIDENT_SCHEMA_VERSION: u32 = 2;

#[derive(Serialize, Deserialize, Clone)]
struct Settings {
    sample_interval_seconds: u64,
    retention_days: u32,
    rolling_limit_gb: u64,
    incident_limit_gb: u64,
    ai_mode: String,
    ollama_endpoint: String,
    ollama_model: String,
    dumps_enabled: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            sample_interval_seconds: 2,
            retention_days: 30,
            rolling_limit_gb: 2,
            incident_limit_gb: 20,
            ai_mode: "disabled".into(),
            ollama_endpoint: "http://127.0.0.1:11434".into(),
            ollama_model: "qwen3:8b".into(),
            dumps_enabled: false,
        }
    }
}
#[derive(Serialize, Deserialize, Clone)]
struct IncidentDraft {
    symptom: String,
    severity: String,
    duration_seconds: u64,
    still_happening: bool,
    description: String,
}
#[derive(Serialize, Deserialize, Clone)]
struct Incident {
    schema_version: u32,
    id: String,
    created_at: String,
    trigger_time: String,
    trigger_source: String,
    symptom: String,
    symptom_label: String,
    severity: String,
    status: String,
    pre_window_seconds: u64,
    post_window_seconds: u64,
    likely_cause: Option<String>,
    confidence: Option<f64>,
    sensitivity_level: u8,
    machine_id: String,
    app_version: String,
}
#[derive(Serialize, Deserialize, Clone)]
struct Observation {
    id: String,
    title: String,
    description: String,
    source: String,
    category: String,
    offset_ms: i64,
    severity: String,
    value: Option<f64>,
    unit: Option<String>,
}
#[derive(Serialize, Deserialize, Clone)]
struct Cause {
    title: String,
    confidence: f64,
    explanation: String,
    supporting_evidence_ids: Vec<String>,
}
#[derive(Serialize, Deserialize, Clone)]
struct Test {
    title: String,
    description: String,
    priority: u8,
}
#[derive(Serialize, Deserialize, Clone)]
struct Report {
    summary: String,
    likely_causes: Vec<Cause>,
    next_tests: Vec<Test>,
    generated_by: String,
}
#[derive(Serialize, Clone)]
struct RawFile {
    name: String,
    kind: String,
    size_bytes: u64,
}
#[derive(Serialize)]
struct CollectionField {
    label: String,
    value: String,
}
#[derive(Serialize)]
struct CollectionCategory {
    id: String,
    label: String,
    description: String,
    status: String,
    quantity: String,
    coverage: Option<String>,
    sensitivity_level: u8,
    size_bytes: u64,
    source_files: Vec<String>,
    details: Vec<CollectionField>,
}
#[derive(Serialize)]
struct CollectionSummary {
    status: String,
    planned_window: String,
    actual_coverage: String,
    sample_count: usize,
    event_count: usize,
    total_size_bytes: u64,
    sensitivity_level: u8,
    categories: Vec<CollectionCategory>,
}
#[derive(Serialize)]
struct DiagnosticMetricPoint {
    timestamp: String,
    offset_ms: i64,
    cpu_percent: f32,
    memory_percent: f64,
    available_memory_bytes: u64,
    commit_percent: f64,
    disk_read_bytes_per_sec: u64,
    disk_write_bytes_per_sec: u64,
    disk_latency_ms: f64,
    disk_queue_length: f64,
    network_bytes_per_sec: u64,
    network_errors: u64,
    network_discards: u64,
    top_processes: Vec<collector::ProcessSample>,
}
#[derive(Serialize)]
struct DiagnosticHighlight {
    label: String,
    value: String,
    description: String,
    offset_ms: i64,
    severity: String,
}
#[derive(Serialize)]
struct DiagnosticProcess {
    pid: u32,
    name: String,
    first_offset_ms: i64,
    last_offset_ms: i64,
    peak_offset_ms: i64,
    sample_count: usize,
    max_cpu_percent: f32,
    max_memory_bytes: u64,
    max_disk_read_bytes_per_sec: u64,
    max_disk_write_bytes_per_sec: u64,
}
#[derive(Serialize)]
struct DiagnosticEvent {
    id: String,
    timestamp: Option<String>,
    offset_ms: i64,
    channel: String,
    provider: String,
    event_id: Option<u32>,
    level: u8,
    level_label: String,
    summary: String,
    details: String,
    computer: String,
}
#[derive(Serialize)]
struct DiagnosticWorkspace {
    points: Vec<DiagnosticMetricPoint>,
    highlights: Vec<DiagnosticHighlight>,
    processes: Vec<DiagnosticProcess>,
    events: Vec<DiagnosticEvent>,
}
#[derive(Serialize)]
struct Detail {
    incident: Incident,
    pinned: bool,
    observations: Vec<Observation>,
    report: Option<Report>,
    raw_files: Vec<RawFile>,
    collection: CollectionSummary,
    diagnostics: DiagnosticWorkspace,
    data_path: String,
}
#[derive(Serialize)]
struct Dashboard {
    monitoring: bool,
    uptime_seconds: u64,
    storage_bytes: u64,
    incident_storage_bytes: u64,
    storage_limit_bytes: u64,
    etw_status: String,
    cpu_percent: f32,
    memory_percent: f64,
    disk_latency_ms: f64,
    network_kbps: f32,
    last_sample_at: Option<String>,
    data_path: String,
    sensitivity_level_max: u8,
    blackbox_cpu_percent: f32,
    blackbox_memory_bytes: u64,
    blackbox_disk_write_kbps: f32,
    effective_interval_seconds: u64,
    shortcut_status: String,
}
#[derive(Serialize, Deserialize, Clone)]
struct RecoveryCandidate {
    detected_at: String,
    previous_session_started_at: String,
    last_sample_at: Option<String>,
}
struct AppState {
    root: PathBuf,
    started: Instant,
    monitoring: Arc<AtomicBool>,
    latest: Arc<Mutex<collector::Sample>>,
    logman_status: Mutex<String>,
    recovery: Mutex<Option<RecoveryCandidate>>,
    io_lock: Arc<Mutex<()>>,
    incident_cancellations: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
    shortcut_status: Mutex<String>,
}

type IncidentCancellations = Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>;

#[derive(Clone)]
struct IncidentRuntime {
    io_lock: Arc<Mutex<()>>,
    monitoring: Arc<AtomicBool>,
    cancellations: IncidentCancellations,
}

fn cancel_incident(cancellations: &IncidentCancellations, id: &str) {
    if let Some(cancellation) = cancellations
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(id)
    {
        cancellation.store(true, Ordering::Release);
    }
}

fn cancel_all_incidents(cancellations: &IncidentCancellations) {
    for cancellation in cancellations
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .values()
    {
        cancellation.store(true, Ordering::Release);
    }
}

fn read_json<T: for<'a> Deserialize<'a>>(path: &Path) -> Result<T, String> {
    serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}
fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).map_err(|e| e.to_string())?
    }
    fs::write(
        path,
        serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}
fn settings_path(s: &AppState) -> PathBuf {
    s.root.join("settings.json")
}
fn incidents_dir(s: &AppState) -> PathBuf {
    s.root.join("incidents")
}
fn load_or_create_machine_id(root: &Path) -> Result<String, String> {
    let path = root.join("machine-id");
    if let Ok(value) = fs::read_to_string(&path) {
        let value = value.trim();
        if !value.is_empty() {
            return Ok(value.to_owned());
        }
    }
    let value = Uuid::new_v4().simple().to_string();
    fs::write(path, &value).map_err(|error| error.to_string())?;
    Ok(value)
}
fn symptom_label(v: &str) -> String {
    match v {
        "system_slow" => "系统卡顿",
        "system_freeze" => "系统无响应",
        "app_hang" => "程序无响应",
        "network_slow" => "网速慢",
        "network_offline" => "网络断开",
        "display_issue" => "黑屏 / 显示异常",
        "auto_restart" => "自动重启",
        "blue_screen" => "蓝屏",
        _ => "其他",
    }
    .into()
}
fn dir_size(path: &Path) -> u64 {
    fs::read_dir(path)
        .map(|x| {
            x.flatten()
                .map(|e| {
                    if e.path().is_dir() {
                        dir_size(&e.path())
                    } else {
                        e.metadata().map(|m| m.len()).unwrap_or(0)
                    }
                })
                .sum()
        })
        .unwrap_or(0)
}
fn format_duration(seconds: u64) -> String {
    let minutes = seconds / 60;
    let remaining = seconds % 60;
    if remaining == 0 {
        format!("{minutes} 分钟")
    } else if minutes == 0 {
        format!("{remaining} 秒")
    } else {
        format!("{minutes} 分 {remaining} 秒")
    }
}
fn format_offset(milliseconds: i64) -> String {
    let sign = if milliseconds < 0 { "−" } else { "+" };
    let seconds = milliseconds.unsigned_abs() / 1000;
    let minutes = seconds / 60;
    let remaining = seconds % 60;
    if minutes == 0 {
        format!("{sign}{remaining} 秒")
    } else if remaining == 0 {
        format!("{sign}{minutes} 分钟")
    } else {
        format!("{sign}{minutes} 分 {remaining} 秒")
    }
}
fn count_xml_events(path: &Path) -> usize {
    fs::read_to_string(path)
        .map(|content| {
            content
                .match_indices("<Event")
                .filter(|(index, _)| {
                    content[*index + 6..]
                        .chars()
                        .next()
                        .is_some_and(|character| character == '>' || character.is_whitespace())
                })
                .count()
        })
        .unwrap_or(0)
}
fn collection_field(label: &str, value: impl Into<String>) -> CollectionField {
    CollectionField {
        label: label.into(),
        value: value.into(),
    }
}
fn source_size(raw_files: &[RawFile], names: &[&str]) -> u64 {
    raw_files
        .iter()
        .filter(|file| names.contains(&file.name.as_str()))
        .map(|file| file.size_bytes)
        .sum()
}
fn source_names(raw_files: &[RawFile], names: &[&str]) -> Vec<String> {
    raw_files
        .iter()
        .filter(|file| names.contains(&file.name.as_str()))
        .map(|file| file.name.clone())
        .collect()
}
fn collection_status(incident: &Incident, available: bool) -> String {
    if available {
        "available"
    } else if ["capturing", "freezing", "extracting"].contains(&incident.status.as_str()) {
        "pending"
    } else if incident.status == "failed" {
        "failed"
    } else {
        "missing"
    }
    .into()
}
fn build_collection(
    dir: &Path,
    incident: &Incident,
    metrics: &[collector::Sample],
    observations: &[Observation],
    report: &Option<Report>,
    raw_files: &[RawFile],
) -> CollectionSummary {
    let trigger_ms = chrono::DateTime::parse_from_rfc3339(&incident.trigger_time)
        .map(|time| time.timestamp_millis())
        .unwrap_or_default();
    let actual_coverage = metrics
        .first()
        .zip(metrics.last())
        .map(|(first, last)| {
            format!(
                "{} 至 {}",
                format_offset(first.timestamp_ms - trigger_ms),
                format_offset(last.timestamp_ms - trigger_ms)
            )
        })
        .unwrap_or_else(|| {
            if ["capturing", "freezing", "extracting"].contains(&incident.status.as_str()) {
                "正在生成".into()
            } else {
                "无性能样本".into()
            }
        });
    let system_events = count_xml_events(&dir.join("evidence/system.xml"));
    let application_events = count_xml_events(&dir.join("evidence/application.xml"));
    let event_count = system_events + application_events;
    let process: serde_json::Value =
        read_json(&dir.join("evidence/process_snapshot.json")).unwrap_or_default();
    let snapshot_processes: Vec<collector::ProcessSample> =
        serde_json::from_value(process["top_processes"].clone()).unwrap_or_default();
    let highest_cpu_process = snapshot_processes
        .iter()
        .max_by(|left, right| left.cpu_percent.total_cmp(&right.cpu_percent));
    let capabilities: Option<capabilities::CapabilityReport> =
        read_json(&dir.join("evidence/capabilities.json")).ok();
    let user_report: Option<IncidentDraft> = read_json(&dir.join("user_report.json")).ok();
    let performance_sources = [
        "evidence/system_snapshot.json",
        "evidence/metrics.jsonl",
        "evidence/performance.blg",
        "evidence/performance-status.txt",
    ];
    let event_sources = [
        "evidence/system.evtx",
        "evidence/application.evtx",
        "evidence/system.xml",
        "evidence/application.xml",
        "evidence/export-errors.txt",
    ];
    let derived_sources = [
        "extracted/facts.json",
        "report/report.json",
        "report/report.md",
        "pipeline-error.txt",
    ];
    let process_available = dir.join("evidence/process_snapshot.json").is_file();
    let capability_available = capabilities.is_some();
    let event_available = event_count > 0
        || dir.join("evidence/system.evtx").is_file()
        || dir.join("evidence/application.evtx").is_file();
    let derived_available = dir.join("extracted/facts.json").is_file() || report.is_some();
    let categories = vec![
        CollectionCategory {
            id: "incident".into(),
            label: "事故信息".into(),
            description: "用户标记故障时生成的时间、症状和窗口配置。".into(),
            status: "available".into(),
            quantity: "1 条事故记录".into(),
            coverage: None,
            sensitivity_level: 1,
            size_bytes: source_size(raw_files, &["incident.json"]),
            source_files: source_names(raw_files, &["incident.json"]),
            details: vec![
                collection_field("故障症状", &incident.symptom_label),
                collection_field("严重程度", &incident.severity),
                collection_field("触发来源", &incident.trigger_source),
                collection_field("应用版本", &incident.app_version),
            ],
        },
        CollectionCategory {
            id: "performance".into(),
            label: "性能指标".into(),
            description: "CPU、内存、磁盘和网络的低开销时间序列。".into(),
            status: collection_status(incident, !metrics.is_empty()),
            quantity: format!("{} 个样本", metrics.len()),
            coverage: Some(actual_coverage.clone()),
            sensitivity_level: 0,
            size_bytes: source_size(raw_files, &performance_sources),
            source_files: source_names(raw_files, &performance_sources),
            details: vec![
                collection_field("实际覆盖", &actual_coverage),
                collection_field(
                    "计划窗口",
                    format!(
                        "故障前 {}，故障后 {}",
                        format_duration(incident.pre_window_seconds),
                        format_duration(incident.post_window_seconds)
                    ),
                ),
                collection_field(
                    "有效采样间隔",
                    metrics
                        .last()
                        .map(|sample| format!("{} 秒", sample.effective_interval_seconds))
                        .unwrap_or_else(|| "尚不可用".into()),
                ),
            ],
        },
        CollectionCategory {
            id: "process".into(),
            label: "进程状态".into(),
            description: "标记事故时 CPU 占用最高的进程快照。".into(),
            status: collection_status(incident, process_available),
            quantity: if process_available {
                "1 份快照".into()
            } else {
                "0 份快照".into()
            },
            coverage: None,
            sensitivity_level: 1,
            size_bytes: source_size(raw_files, &["evidence/process_snapshot.json"]),
            source_files: source_names(raw_files, &["evidence/process_snapshot.json"]),
            details: vec![
                collection_field(
                    "最高占用进程",
                    highest_cpu_process
                        .map(|process| process.name.as_str())
                        .unwrap_or("未识别"),
                ),
                collection_field(
                    "进程 CPU",
                    highest_cpu_process
                        .map(|process| format!("{:.1}%", process.cpu_percent))
                        .unwrap_or_else(|| "未知".into()),
                ),
                collection_field("进程数量", format!("Top {}", snapshot_processes.len())),
            ],
        },
        CollectionCategory {
            id: "events".into(),
            label: "Windows 事件".into(),
            description: "事故窗口内筛选的 System 与 Application 事件。".into(),
            status: collection_status(incident, event_available),
            quantity: format!("{event_count} 条筛选事件"),
            coverage: Some(actual_coverage.clone()),
            sensitivity_level: 2,
            size_bytes: source_size(raw_files, &event_sources),
            source_files: source_names(raw_files, &event_sources),
            details: vec![
                collection_field("System", format!("{system_events} 条")),
                collection_field("Application", format!("{application_events} 条")),
                collection_field(
                    "原始 EVTX",
                    if dir.join("evidence/system.evtx").is_file()
                        || dir.join("evidence/application.evtx").is_file()
                    {
                        "已保存"
                    } else {
                        "未生成"
                    },
                ),
            ],
        },
        CollectionCategory {
            id: "environment".into(),
            label: "诊断环境".into(),
            description: "事故发生时可用的系统诊断组件与权限状态。".into(),
            status: collection_status(incident, capability_available),
            quantity: capabilities
                .as_ref()
                .map(|value| format!("{} 项能力", value.capabilities.len()))
                .unwrap_or_else(|| "0 项能力".into()),
            coverage: None,
            sensitivity_level: 1,
            size_bytes: source_size(raw_files, &["evidence/capabilities.json"]),
            source_files: source_names(raw_files, &["evidence/capabilities.json"]),
            details: vec![
                collection_field(
                    "可用能力",
                    capabilities
                        .as_ref()
                        .map(|value| format!("{} 项", value.available))
                        .unwrap_or_else(|| "未知".into()),
                ),
                collection_field(
                    "需要处理",
                    capabilities
                        .as_ref()
                        .map(|value| format!("{} 项", value.attention))
                        .unwrap_or_else(|| "未知".into()),
                ),
                collection_field(
                    "提升权限",
                    capabilities
                        .as_ref()
                        .map(|value| if value.is_elevated { "是" } else { "否" })
                        .unwrap_or("未知"),
                ),
            ],
        },
        CollectionCategory {
            id: "user_report".into(),
            label: "用户报告".into(),
            description: "标记事故时由用户主动选择或填写的信息。".into(),
            status: collection_status(incident, user_report.is_some()),
            quantity: "1 份报告".into(),
            coverage: None,
            sensitivity_level: 2,
            size_bytes: source_size(raw_files, &["user_report.json"]),
            source_files: source_names(raw_files, &["user_report.json"]),
            details: vec![
                collection_field(
                    "持续时间",
                    user_report
                        .as_ref()
                        .map(|value| format_duration(value.duration_seconds))
                        .unwrap_or_else(|| "未知".into()),
                ),
                collection_field(
                    "仍在发生",
                    user_report
                        .as_ref()
                        .map(|value| if value.still_happening { "是" } else { "否" })
                        .unwrap_or("未知"),
                ),
                collection_field(
                    "补充描述",
                    user_report
                        .as_ref()
                        .map(|value| {
                            if value.description.trim().is_empty() {
                                "未填写".into()
                            } else {
                                value.description.clone()
                            }
                        })
                        .unwrap_or_else(|| "未填写".into()),
                ),
            ],
        },
        CollectionCategory {
            id: "derived".into(),
            label: "程序生成的数据".into(),
            description: "从本地证据提取的观察结果和分析报告，不是额外采集。".into(),
            status: collection_status(incident, derived_available),
            quantity: format!(
                "{} 条观察 · {}",
                observations.len(),
                if report.is_some() {
                    "1 份报告"
                } else {
                    "无报告"
                }
            ),
            coverage: None,
            sensitivity_level: 1,
            size_bytes: source_size(raw_files, &derived_sources),
            source_files: source_names(raw_files, &derived_sources),
            details: vec![
                collection_field("结构化观察", format!("{} 条", observations.len())),
                collection_field(
                    "分析报告",
                    if report.is_some() {
                        "已生成"
                    } else {
                        "未生成"
                    },
                ),
                collection_field("数据来源", "仅来自本事故包的本地证据"),
            ],
        },
    ];
    let partial = categories
        .iter()
        .any(|category| ["missing", "failed"].contains(&category.status.as_str()));
    CollectionSummary {
        status: if ["capturing", "freezing", "extracting"].contains(&incident.status.as_str()) {
            "pending"
        } else if incident.status == "failed" {
            "failed"
        } else if partial {
            "partial"
        } else {
            "complete"
        }
        .into(),
        planned_window: format!(
            "−{} / +{}",
            format_duration(incident.pre_window_seconds),
            format_duration(incident.post_window_seconds)
        ),
        actual_coverage,
        sample_count: metrics.len(),
        event_count,
        total_size_bytes: dir_size(dir),
        sensitivity_level: categories
            .iter()
            .map(|category| category.sensitivity_level)
            .max()
            .unwrap_or(0),
        categories,
    }
}
fn load_incident_metrics(dir: &Path) -> Vec<collector::Sample> {
    fs::read_to_string(dir.join("evidence/metrics.jsonl"))
        .map(|content| {
            content
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect()
        })
        .unwrap_or_default()
}
fn compact_text(value: &str, limit: usize) -> String {
    let compact = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() <= limit {
        compact
    } else {
        format!("{}…", compact.chars().take(limit).collect::<String>())
    }
}
fn event_level(level: Option<u8>) -> (u8, &'static str) {
    match level.unwrap_or(4) {
        1 => (1, "关键"),
        2 => (2, "错误"),
        3 => (3, "警告"),
        5 => (5, "详细"),
        _ => (4, "信息"),
    }
}
fn build_diagnostics(
    dir: &Path,
    incident: &Incident,
    metrics: &[collector::Sample],
) -> DiagnosticWorkspace {
    let trigger_ms = chrono::DateTime::parse_from_rfc3339(&incident.trigger_time)
        .map(|time| time.timestamp_millis())
        .unwrap_or_default();
    let points = metrics
        .iter()
        .map(|sample| DiagnosticMetricPoint {
            timestamp: sample.timestamp.clone(),
            offset_ms: sample.timestamp_ms - trigger_ms,
            cpu_percent: sample.cpu_percent,
            memory_percent: sample.memory_percent,
            available_memory_bytes: sample.available_memory_bytes,
            commit_percent: sample.commit_percent,
            disk_read_bytes_per_sec: sample.disk_read_bytes_per_sec,
            disk_write_bytes_per_sec: sample.disk_write_bytes_per_sec,
            disk_latency_ms: sample.disk_latency_ms,
            disk_queue_length: sample.disk_queue_length,
            network_bytes_per_sec: sample.network_bytes_per_sec,
            network_errors: sample.network_errors,
            network_discards: sample.network_discards,
            top_processes: sample.top_processes.clone(),
        })
        .collect();

    let mut process_map: HashMap<(u32, String), DiagnosticProcess> = HashMap::new();
    for sample in metrics {
        let offset_ms = sample.timestamp_ms - trigger_ms;
        for process in &sample.top_processes {
            let entry = process_map
                .entry((process.pid, process.name.clone()))
                .or_insert_with(|| DiagnosticProcess {
                    pid: process.pid,
                    name: process.name.clone(),
                    first_offset_ms: offset_ms,
                    last_offset_ms: offset_ms,
                    peak_offset_ms: offset_ms,
                    sample_count: 0,
                    max_cpu_percent: 0.0,
                    max_memory_bytes: 0,
                    max_disk_read_bytes_per_sec: 0,
                    max_disk_write_bytes_per_sec: 0,
                });
            entry.first_offset_ms = entry.first_offset_ms.min(offset_ms);
            entry.last_offset_ms = entry.last_offset_ms.max(offset_ms);
            entry.sample_count += 1;
            if process.cpu_percent > entry.max_cpu_percent {
                entry.max_cpu_percent = process.cpu_percent;
                entry.peak_offset_ms = offset_ms;
            }
            entry.max_memory_bytes = entry.max_memory_bytes.max(process.memory_bytes);
            entry.max_disk_read_bytes_per_sec = entry
                .max_disk_read_bytes_per_sec
                .max(process.disk_read_bytes_per_sec);
            entry.max_disk_write_bytes_per_sec = entry
                .max_disk_write_bytes_per_sec
                .max(process.disk_write_bytes_per_sec);
        }
    }
    let mut processes = process_map.into_values().collect::<Vec<_>>();
    let process_score = |process: &DiagnosticProcess| {
        process.max_cpu_percent as f64
            + process.max_memory_bytes as f64 / 1_073_741_824.0 * 5.0
            + (process.max_disk_read_bytes_per_sec + process.max_disk_write_bytes_per_sec) as f64
                / 1_048_576.0
    };
    processes.sort_by(|left, right| {
        process_score(right)
            .partial_cmp(&process_score(left))
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut event_records = analysis::parse_windows_events(
        &fs::read_to_string(dir.join("evidence/system.xml")).unwrap_or_default(),
        "System",
    );
    event_records.extend(analysis::parse_windows_events(
        &fs::read_to_string(dir.join("evidence/application.xml")).unwrap_or_default(),
        "Application",
    ));
    let mut events = event_records
        .into_iter()
        .enumerate()
        .map(|(index, event)| {
            let offset_ms = event
                .timestamp
                .as_deref()
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .map(|value| value.timestamp_millis() - trigger_ms)
                .unwrap_or_default();
            let (level, level_label) = event_level(event.level);
            let data = event.data.join("\n");
            let details = if event.message.is_empty() {
                data.clone()
            } else if data.is_empty() {
                event.message.clone()
            } else {
                format!("{}\n\n{}", event.message, data)
            };
            let summary_source = if !event.message.is_empty() {
                &event.message
            } else if !data.is_empty() {
                &data
            } else {
                &event.provider
            };
            let summary = compact_text(summary_source, 180);
            DiagnosticEvent {
                id: format!("event_{:03}", index + 1),
                timestamp: event.timestamp,
                offset_ms,
                channel: event.channel,
                provider: event.provider,
                event_id: event.event_id,
                level,
                level_label: level_label.into(),
                summary,
                details,
                computer: event.computer,
            }
        })
        .collect::<Vec<_>>();
    events.sort_by_key(|event| event.offset_ms);

    let mut highlights = Vec::new();
    if let Some(sample) = metrics
        .iter()
        .max_by(|left, right| left.cpu_percent.total_cmp(&right.cpu_percent))
    {
        highlights.push(DiagnosticHighlight {
            label: "CPU 峰值".into(),
            value: format!("{:.1}%", sample.cpu_percent),
            description: if sample.cpu_percent >= 90.0 {
                "达到持续饱和排查阈值"
            } else if sample.cpu_percent >= 75.0 {
                "负载明显升高"
            } else {
                "未达到内置异常阈值"
            }
            .into(),
            offset_ms: sample.timestamp_ms - trigger_ms,
            severity: if sample.cpu_percent >= 90.0 {
                "critical"
            } else if sample.cpu_percent >= 75.0 {
                "warning"
            } else {
                "info"
            }
            .into(),
        });
    }
    if let Some(sample) = metrics.iter().max_by(|left, right| {
        left.memory_percent
            .total_cmp(&right.memory_percent)
            .then_with(|| {
                right
                    .available_memory_bytes
                    .cmp(&left.available_memory_bytes)
            })
    }) {
        highlights.push(DiagnosticHighlight {
            label: "内存峰值".into(),
            value: format!("{:.1}%", sample.memory_percent),
            description: format!(
                "最低可用内存 {}",
                format_bytes(sample.available_memory_bytes)
            ),
            offset_ms: sample.timestamp_ms - trigger_ms,
            severity: if sample.memory_percent >= 90.0 {
                "critical"
            } else if sample.memory_percent >= 80.0 {
                "warning"
            } else {
                "info"
            }
            .into(),
        });
    }
    if let Some(sample) = metrics
        .iter()
        .max_by(|left, right| left.disk_latency_ms.total_cmp(&right.disk_latency_ms))
    {
        highlights.push(DiagnosticHighlight {
            label: "磁盘延迟峰值".into(),
            value: format!("{:.1} ms", sample.disk_latency_ms),
            description: format!("同时队列长度 {:.1}", sample.disk_queue_length),
            offset_ms: sample.timestamp_ms - trigger_ms,
            severity: if sample.disk_latency_ms >= 100.0 {
                "critical"
            } else if sample.disk_latency_ms >= 30.0 {
                "warning"
            } else {
                "info"
            }
            .into(),
        });
    }
    if let Some(sample) = metrics
        .iter()
        .max_by_key(|sample| sample.network_bytes_per_sec)
    {
        let network_errors = metrics
            .iter()
            .map(|point| point.network_errors + point.network_discards)
            .sum::<u64>();
        highlights.push(DiagnosticHighlight {
            label: "网络吞吐峰值".into(),
            value: format!("{}/s", format_bytes(sample.network_bytes_per_sec)),
            description: format!("窗口内错误与丢弃 {network_errors} 个"),
            offset_ms: sample.timestamp_ms - trigger_ms,
            severity: if network_errors > 0 {
                "warning"
            } else {
                "info"
            }
            .into(),
        });
    }
    let important_events = events.iter().filter(|event| event.level <= 2).count();
    highlights.push(DiagnosticHighlight {
        label: "关键 Windows 事件".into(),
        value: format!("{important_events} 条"),
        description: format!("共解析 {} 条筛选事件", events.len()),
        offset_ms: events
            .iter()
            .filter(|event| event.level <= 2)
            .min_by_key(|event| event.offset_ms.unsigned_abs())
            .map(|event| event.offset_ms)
            .unwrap_or_default(),
        severity: if important_events > 0 {
            "warning"
        } else {
            "info"
        }
        .into(),
    });

    DiagnosticWorkspace {
        points,
        highlights,
        processes,
        events,
    }
}
fn format_bytes(value: u64) -> String {
    if value < 1024 {
        format!("{value} B")
    } else if value < 1_048_576 {
        format!("{:.1} KB", value as f64 / 1024.0)
    } else if value < 1_073_741_824 {
        format!("{:.1} MB", value as f64 / 1_048_576.0)
    } else {
        format!("{:.2} GB", value as f64 / 1_073_741_824.0)
    }
}
fn load_incidents(s: &AppState) -> Vec<Incident> {
    let mut v: Vec<Incident> = fs::read_dir(incidents_dir(s))
        .map(|r| {
            r.flatten()
                .filter_map(|e| read_json(&e.path().join("incident.json")).ok())
                .collect()
        })
        .unwrap_or_default();
    v.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    v
}
fn discard_unsupported_incidents(root: &Path) -> Result<usize, String> {
    let directory = root.join("incidents");
    let mut removed = 0;
    for entry in fs::read_dir(&directory)
        .map_err(|error| error.to_string())?
        .flatten()
    {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let manifest = path.join("incident.json");
        let Ok(bytes) = fs::read(&manifest) else {
            continue;
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        if value["schema_version"].as_u64() != Some(INCIDENT_SCHEMA_VERSION as u64) {
            let id = value["id"].as_str().map(str::to_owned).or_else(|| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .map(str::to_owned)
            });
            fs::remove_dir_all(path).map_err(|error| error.to_string())?;
            if let Some(id) = id {
                storage::delete_incident(root, &id)?;
            }
            removed += 1;
        }
    }
    Ok(removed)
}
fn build_detail(s: &AppState, i: Incident) -> Result<Detail, String> {
    let dir = incidents_dir(s).join(&i.id);
    let metrics = load_incident_metrics(&dir);
    let observations: Vec<Observation> =
        read_json(&dir.join("extracted/facts.json")).unwrap_or_default();
    let report = read_json(&dir.join("report/report.json")).ok();
    let mut raw = vec![];
    for name in [
        "incident.json",
        "user_report.json",
        "evidence/system_snapshot.json",
        "evidence/capabilities.json",
        "evidence/process_snapshot.json",
        "evidence/metrics.jsonl",
        "evidence/performance.blg",
        "evidence/system.evtx",
        "evidence/application.evtx",
        "evidence/system.xml",
        "evidence/application.xml",
        "evidence/performance-status.txt",
        "evidence/export-errors.txt",
        "extracted/facts.json",
        "report/report.json",
        "report/report.md",
        "pipeline-error.txt",
    ] {
        let p = dir.join(name);
        if let Ok(m) = fs::metadata(&p) {
            raw.push(RawFile {
                name: name.into(),
                kind: match Path::new(name).extension().and_then(|value| value.to_str()) {
                    Some("json") => "JSON",
                    Some("jsonl") => "JSON Lines",
                    Some("evtx") => "Windows 事件日志",
                    Some("blg") => "Windows 性能日志",
                    Some("xml") => "筛选事件 XML",
                    Some("md") => "Markdown 报告",
                    _ => "状态日志",
                }
                .into(),
                size_bytes: m.len(),
            })
        }
    }
    let collection = build_collection(&dir, &i, &metrics, &observations, &report, &raw);
    let diagnostics = build_diagnostics(&dir, &i, &metrics);
    Ok(Detail {
        incident: i,
        pinned: dir.join(".pinned").exists(),
        observations,
        report,
        raw_files: raw,
        collection,
        diagnostics,
        data_path: dir.to_string_lossy().into(),
    })
}

#[tauri::command]
fn get_settings(s: State<AppState>) -> Settings {
    read_json(&settings_path(&s)).unwrap_or_default()
}
#[tauri::command]
fn save_settings(s: State<AppState>, settings: Settings) -> Result<Settings, String> {
    validate_settings(&settings)?;
    write_json(&settings_path(&s), &settings)?;
    if s.monitoring.load(Ordering::Relaxed) {
        let status = collector::start_logman(
            &s.root,
            settings.sample_interval_seconds,
            settings.rolling_limit_gb * 768,
        );
        *s.logman_status.lock().unwrap() = status;
    }
    storage::audit(&s.root, "settings.updated", None, None)?;
    Ok(settings)
}

fn validate_settings(settings: &Settings) -> Result<(), String> {
    if ![1, 2, 5, 10].contains(&settings.sample_interval_seconds) {
        return Err("采样间隔只允许 1、2、5 或 10 秒".into());
    }
    if ![0, 7, 30, 90].contains(&settings.retention_days) {
        return Err("事故保留期限无效".into());
    }
    if !(1..=8).contains(&settings.rolling_limit_gb) {
        return Err("循环数据上限必须在 1–8 GB 之间".into());
    }
    if !(1..=100).contains(&settings.incident_limit_gb) {
        return Err("事故数据上限必须在 1–100 GB 之间".into());
    }
    if !matches!(settings.ai_mode.as_str(), "disabled" | "ollama") {
        return Err("AI 模式无效".into());
    }
    if settings.ai_mode == "ollama" {
        if !ai::is_local_endpoint(&settings.ollama_endpoint) {
            return Err("Ollama 地址必须是 localhost、127.0.0.1 或 ::1".into());
        }
        if settings.ollama_model.trim().is_empty() {
            return Err("Ollama 模型名称不能为空".into());
        }
    }
    if settings.dumps_enabled {
        return Err("MVP 尚未启用 Dump 采集；该高敏感功能保持关闭".into());
    }
    Ok(())
}
#[tauri::command]
fn list_incidents(s: State<AppState>) -> Vec<Incident> {
    load_incidents(&s)
}
#[tauri::command]
fn get_dashboard(s: State<AppState>) -> Dashboard {
    let cfg: Settings = read_json(&settings_path(&s)).unwrap_or_default();
    let sample = s.latest.lock().unwrap().clone();
    Dashboard {
        monitoring: s.monitoring.load(Ordering::Relaxed),
        uptime_seconds: s.started.elapsed().as_secs(),
        storage_bytes: dir_size(&s.root.join("rolling")),
        incident_storage_bytes: dir_size(&s.root.join("incidents")),
        storage_limit_bytes: cfg.rolling_limit_gb * 1_073_741_824,
        etw_status: s.logman_status.lock().unwrap().clone(),
        cpu_percent: sample.cpu_percent,
        memory_percent: sample.memory_percent,
        disk_latency_ms: sample.disk_latency_ms,
        network_kbps: sample.network_bytes_per_sec as f32 / 1024.0,
        last_sample_at: (!sample.timestamp.is_empty()).then_some(sample.timestamp),
        data_path: s.root.to_string_lossy().into_owned(),
        sensitivity_level_max: load_incidents(&s)
            .iter()
            .map(|incident| incident.sensitivity_level)
            .max()
            .unwrap_or(0),
        blackbox_cpu_percent: sample.blackbox_cpu_percent,
        blackbox_memory_bytes: sample.blackbox_memory_bytes,
        blackbox_disk_write_kbps: sample.blackbox_disk_write_bytes_per_sec as f32 / 1024.0,
        effective_interval_seconds: sample.effective_interval_seconds,
        shortcut_status: s
            .shortcut_status
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone(),
    }
}
#[tauri::command]
async fn get_diagnostic_capabilities(
    s: State<'_, AppState>,
) -> Result<capabilities::CapabilityReport, String> {
    let settings: Settings = read_json(&settings_path(&s)).unwrap_or_default();
    let logman_status = s
        .logman_status
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    let report = capabilities::detect(&s.root, &settings, &logman_status).await;
    let _guard = s.io_lock.lock().unwrap_or_else(|error| error.into_inner());
    write_json(&s.root.join("capabilities.json"), &report)?;
    Ok(report)
}
#[tauri::command]
fn set_monitoring(s: State<AppState>, enabled: bool) -> Dashboard {
    s.monitoring.store(enabled, Ordering::Relaxed);
    let settings: Settings = read_json(&settings_path(&s)).unwrap_or_default();
    let status = if enabled {
        collector::start_logman(
            &s.root,
            settings.sample_interval_seconds,
            settings.rolling_limit_gb * 768,
        )
    } else {
        collector::stop_logman();
        "已暂停".into()
    };
    *s.logman_status.lock().unwrap() = status;
    let _ = storage::audit(
        &s.root,
        if enabled {
            "monitoring.started"
        } else {
            "monitoring.stopped"
        },
        None,
        None,
    );
    get_dashboard(s)
}
#[tauri::command]
fn create_incident(
    s: State<AppState>,
    draft: IncidentDraft,
    trigger_time: Option<String>,
) -> Result<Detail, String> {
    let latest = s.latest.lock().unwrap().clone();
    if let Some(value) = trigger_time.as_deref() {
        collector::parse_time(value)?;
    }
    let incident = create_incident_internal(
        &s.root,
        &latest,
        draft,
        trigger_time,
        "manual",
        IncidentRuntime {
            io_lock: s.io_lock.clone(),
            monitoring: s.monitoring.clone(),
            cancellations: s.incident_cancellations.clone(),
        },
    )?;
    build_detail(&s, incident)
}

fn create_incident_internal(
    root: &Path,
    latest: &collector::Sample,
    draft: IncidentDraft,
    trigger_override: Option<String>,
    trigger_source: &str,
    runtime: IncidentRuntime,
) -> Result<Incident, String> {
    validate_incident_draft(&draft)?;
    if !["manual", "shortcut", "tray", "recovery", "automatic"].contains(&trigger_source) {
        return Err("事故触发来源无效".into());
    }
    let _guard = runtime
        .io_lock
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let now = Utc::now().to_rfc3339();
    let id = Uuid::new_v4().simple().to_string()[..8].to_string();
    let incident = Incident {
        schema_version: INCIDENT_SCHEMA_VERSION,
        id: id.clone(),
        created_at: now.clone(),
        trigger_time: trigger_override.unwrap_or(now),
        trigger_source: trigger_source.into(),
        symptom: draft.symptom.clone(),
        symptom_label: symptom_label(&draft.symptom),
        severity: draft.severity.clone(),
        status: "capturing".into(),
        pre_window_seconds: if draft.symptom.starts_with("network") {
            900
        } else {
            600
        },
        post_window_seconds: if draft.symptom.starts_with("network") {
            300
        } else {
            120
        },
        likely_cause: None,
        confidence: None,
        sensitivity_level: 2,
        machine_id: load_or_create_machine_id(root)?,
        app_version: env!("CARGO_PKG_VERSION").into(),
    };
    let dir = root.join("incidents").join(&id);
    write_json(&dir.join("incident.json"), &incident)?;
    write_json(&dir.join("user_report.json"), &draft)?;
    write_json(&dir.join("evidence/system_snapshot.json"), latest)?;
    if root.join("capabilities.json").is_file() {
        fs::copy(
            root.join("capabilities.json"),
            dir.join("evidence/capabilities.json"),
        )
        .map_err(|error| error.to_string())?;
    }
    write_json(
        &dir.join("evidence/process_snapshot.json"),
        &serde_json::json!({
            "timestamp": latest.timestamp,
            "top_processes": latest.top_processes,
            "source": "sysinfo process snapshot"
        }),
    )?;
    write_json(
        &dir.join("extracted/facts.json"),
        &Vec::<Observation>::new(),
    )?;
    storage::upsert_incident(root, &incident)?;
    storage::audit(root, "incident.created", Some(&id), Some(&draft.symptom))?;
    let worker_root = root.to_path_buf();
    let worker_id = id.clone();
    let worker_io_lock = runtime.io_lock.clone();
    let worker_monitoring = runtime.monitoring.clone();
    let cancellation = Arc::new(AtomicBool::new(false));
    runtime
        .cancellations
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(id.clone(), cancellation.clone());
    let worker_cancellations = runtime.cancellations.clone();
    if let Err(error) = thread::Builder::new()
        .name(format!("incident-{worker_id}"))
        .spawn(move || {
            finalize_incident(
                &worker_root,
                &worker_id,
                worker_io_lock,
                worker_monitoring,
                cancellation,
            );
            worker_cancellations
                .lock()
                .unwrap_or_else(|value| value.into_inner())
                .remove(&worker_id);
        })
    {
        runtime
            .cancellations
            .lock()
            .unwrap_or_else(|value| value.into_inner())
            .remove(&id);
        return Err(error.to_string());
    }
    Ok(incident)
}

fn validate_incident_draft(draft: &IncidentDraft) -> Result<(), String> {
    if ![
        "system_slow",
        "system_freeze",
        "app_hang",
        "network_slow",
        "network_offline",
        "display_issue",
        "auto_restart",
        "blue_screen",
        "other",
    ]
    .contains(&draft.symptom.as_str())
    {
        return Err("症状类型无效".into());
    }
    if !["low", "medium", "high", "critical"].contains(&draft.severity.as_str()) {
        return Err("严重程度无效".into());
    }
    if draft.duration_seconds > 86_400 {
        return Err("持续时间超出允许范围".into());
    }
    if draft.description.chars().count() > 1_000 {
        return Err("补充描述不能超过 1000 个字符".into());
    }
    Ok(())
}
#[tauri::command]
fn get_incident(s: State<AppState>, id: String) -> Result<Detail, String> {
    let i = read_json(&incidents_dir(&s).join(&id).join("incident.json"))?;
    build_detail(&s, i)
}
#[tauri::command]
async fn analyze_incident(s: State<'_, AppState>, id: String) -> Result<Detail, String> {
    let dir = incidents_dir(&s).join(&id);
    let (mut i, obs) = {
        let _guard = s.io_lock.lock().unwrap_or_else(|error| error.into_inner());
        let mut incident: Incident = read_json(&dir.join("incident.json"))?;
        if incident.status != "ready_for_analysis" && incident.status != "completed" {
            return Err(format!(
                "事故证据仍在处理中（当前状态：{}）",
                incident.status
            ));
        }
        let observations: Vec<Observation> = read_json(&dir.join("extracted/facts.json"))?;
        incident.status = "analyzing".into();
        write_json(&dir.join("incident.json"), &incident)?;
        (incident, observations)
    };
    let settings: Settings = read_json(&settings_path(&s)).unwrap_or_default();
    let report = if settings.ai_mode == "ollama" {
        match ai::analyze(&settings, &i, &obs).await {
            Ok(report) => report,
            Err(error) => {
                let _guard = s.io_lock.lock().unwrap_or_else(|value| value.into_inner());
                if dir.exists() {
                    i.status = "ready_for_analysis".into();
                    write_json(&dir.join("incident.json"), &i)?;
                }
                return Err(error);
            }
        }
    } else {
        analysis::deterministic_report(&i.symptom_label, &obs)
    };
    let _guard = s.io_lock.lock().unwrap_or_else(|error| error.into_inner());
    if !dir.exists() {
        return Err("事故在分析期间已被删除".into());
    }
    write_json(&dir.join("report/report.json"), &report)?;
    write_report_markdown(&dir.join("report/report.md"), &i, &report)?;
    i.status = "completed".into();
    i.likely_cause = report
        .likely_causes
        .first()
        .map(|cause| cause.title.clone());
    i.confidence = report.likely_causes.first().map(|cause| cause.confidence);
    write_json(&dir.join("incident.json"), &i)?;
    storage::save_report(&s.root, &id, &report)?;
    storage::upsert_incident(&s.root, &i)?;
    storage::audit(
        &s.root,
        "incident.analyzed",
        Some(&id),
        Some(&report.generated_by),
    )?;
    build_detail(&s, i)
}

fn write_report_markdown(path: &Path, incident: &Incident, report: &Report) -> Result<(), String> {
    let mut markdown = format!(
        "# 系统黑盒子事故报告\n\n- 事故 ID：{}\n- 症状：{}\n- 触发时间：{}\n- 触发来源：{}\n- 应用版本：{}\n- 生成方式：{}\n\n## 摘要\n\n{}\n\n## 可能原因\n\n",
        incident.id,
        incident.symptom_label,
        incident.trigger_time,
        incident.trigger_source,
        incident.app_version,
        report.generated_by,
        report.summary
    );
    if report.likely_causes.is_empty() {
        markdown.push_str("现有证据不足以给出原因排序。\n");
    }
    for cause in &report.likely_causes {
        markdown.push_str(&format!(
            "### {}（可信度 {:.0}%）\n\n{}\n\n证据：{}\n\n",
            cause.title,
            cause.confidence * 100.0,
            cause.explanation,
            cause.supporting_evidence_ids.join("、")
        ));
    }
    markdown.push_str("## 下一步验证\n\n");
    for test in &report.next_tests {
        markdown.push_str(&format!(
            "{}. **{}**：{}\n",
            test.priority, test.title, test.description
        ));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(path, markdown).map_err(|error| error.to_string())
}
#[tauri::command]
fn delete_incident(s: State<AppState>, id: String) -> Result<(), String> {
    cancel_incident(&s.incident_cancellations, &id);
    let _guard = s.io_lock.lock().unwrap_or_else(|error| error.into_inner());
    let p = incidents_dir(&s).join(&id);
    if p.exists() {
        fs::remove_dir_all(p).map_err(|e| e.to_string())?
    }
    storage::delete_incident(&s.root, &id)?;
    storage::audit(&s.root, "incident.deleted", Some(&id), None)?;
    Ok(())
}

#[tauri::command]
fn set_incident_pinned(s: State<AppState>, id: String, pinned: bool) -> Result<Detail, String> {
    let _guard = s.io_lock.lock().unwrap_or_else(|error| error.into_inner());
    let dir = incidents_dir(&s).join(&id);
    if !dir.is_dir() {
        return Err("事故不存在".into());
    }
    let marker = dir.join(".pinned");
    if pinned {
        fs::write(&marker, b"pinned").map_err(|error| error.to_string())?;
    } else if marker.exists() {
        fs::remove_file(&marker).map_err(|error| error.to_string())?;
    }
    storage::audit(
        &s.root,
        if pinned {
            "incident.pinned"
        } else {
            "incident.unpinned"
        },
        Some(&id),
        None,
    )?;
    let incident = read_json(&dir.join("incident.json"))?;
    build_detail(&s, incident)
}
#[tauri::command]
fn delete_all_incidents(s: State<AppState>) -> Result<(), String> {
    cancel_all_incidents(&s.incident_cancellations);
    let _guard = s.io_lock.lock().unwrap_or_else(|error| error.into_inner());
    let p = incidents_dir(&s);
    if p.exists() {
        fs::remove_dir_all(&p).map_err(|e| e.to_string())?
    }
    fs::create_dir_all(p).map_err(|e| e.to_string())?;
    storage::clear_incidents(&s.root)?;
    storage::audit(&s.root, "incidents.deleted_all", None, None)
}

#[tauri::command]
fn delete_all_data(s: State<AppState>) -> Result<Dashboard, String> {
    cancel_all_incidents(&s.incident_cancellations);
    let was_enabled = s.monitoring.swap(false, Ordering::Relaxed);
    let deletion_result = {
        let _guard = s.io_lock.lock().unwrap_or_else(|error| error.into_inner());
        (|| -> Result<(), String> {
            collector::stop_logman();
            for path in [incidents_dir(&s), s.root.join("rolling")] {
                if path.exists() {
                    fs::remove_dir_all(&path).map_err(|error| error.to_string())?;
                }
                fs::create_dir_all(path).map_err(|error| error.to_string())?;
            }
            storage::clear_all_data(&s.root)?;
            let machine_id = s.root.join("machine-id");
            if machine_id.exists() {
                fs::remove_file(machine_id).map_err(|error| error.to_string())?;
            }
            *s.latest.lock().unwrap_or_else(|error| error.into_inner()) =
                collector::Sample::default();
            Ok(())
        })()
    };
    if was_enabled {
        let settings: Settings = read_json(&settings_path(&s)).unwrap_or_default();
        let status = collector::start_logman(
            &s.root,
            settings.sample_interval_seconds,
            settings.rolling_limit_gb * 768,
        );
        *s.logman_status
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = status;
        s.monitoring.store(true, Ordering::Relaxed);
    } else {
        *s.logman_status
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = "已暂停".into();
    }
    deletion_result?;
    Ok(get_dashboard(s))
}

#[tauri::command]
fn get_recovery_candidate(s: State<AppState>) -> Option<RecoveryCandidate> {
    s.recovery.lock().unwrap().clone()
}

#[tauri::command]
fn resolve_recovery(s: State<AppState>, create: bool) -> Result<Option<Detail>, String> {
    let candidate = s
        .recovery
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take();
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    if !create {
        storage::audit(&s.root, "recovery.dismissed", None, None)?;
        return Ok(None);
    }
    let latest = s.latest.lock().unwrap().clone();
    let trigger_time = candidate.last_sample_at.clone();
    let incident = match create_incident_internal(
        &s.root,
        &latest,
        IncidentDraft {
            symptom: "auto_restart".into(),
            severity: "high".into(),
            duration_seconds: 0,
            still_happening: false,
            description: "检测到上次系统黑盒子会话未正常结束".into(),
        },
        trigger_time,
        "recovery",
        IncidentRuntime {
            io_lock: s.io_lock.clone(),
            monitoring: s.monitoring.clone(),
            cancellations: s.incident_cancellations.clone(),
        },
    ) {
        Ok(incident) => incident,
        Err(error) => {
            *s.recovery.lock().unwrap_or_else(|value| value.into_inner()) = Some(candidate);
            return Err(error);
        }
    };
    storage::audit(
        &s.root,
        "recovery.incident_created",
        Some(&incident.id),
        None,
    )?;
    build_detail(&s, incident).map(Some)
}

fn incident_cancelled(cancellation: &AtomicBool) -> bool {
    cancellation.load(Ordering::Acquire)
}

fn wait_for_incident_window(target_end_ms: i64, cancellation: &AtomicBool) -> bool {
    loop {
        if incident_cancelled(cancellation) {
            return false;
        }
        let remaining_ms = target_end_ms.saturating_sub(Utc::now().timestamp_millis());
        if remaining_ms <= 0 {
            return true;
        }
        thread::sleep(Duration::from_millis(remaining_ms.min(100) as u64));
    }
}

fn finalize_incident(
    root: &Path,
    id: &str,
    io_lock: Arc<Mutex<()>>,
    monitoring: Arc<AtomicBool>,
    cancellation: Arc<AtomicBool>,
) {
    let dir = root.join("incidents").join(id);
    let result = (|| -> Result<(), String> {
        let mut incident: Incident = read_json(&dir.join("incident.json"))?;
        let trigger = collector::parse_time(&incident.trigger_time)?.timestamp_millis();
        let target_end = trigger + incident.post_window_seconds as i64 * 1000;
        if !wait_for_incident_window(target_end, &cancellation) {
            return Ok(());
        }
        let _guard = io_lock.lock().unwrap_or_else(|error| error.into_inner());
        if incident_cancelled(&cancellation) || !dir.is_dir() {
            return Ok(());
        }
        incident.status = "freezing".into();
        write_json(&dir.join("incident.json"), &incident)?;

        let start = trigger - incident.pre_window_seconds as i64 * 1000;
        let end = trigger + incident.post_window_seconds as i64 * 1000;
        let evidence = dir.join("evidence");
        let samples = collector::freeze_window(root, &evidence, start, end)?;
        if incident_cancelled(&cancellation) {
            return Ok(());
        }
        let settings: Settings = read_json(&root.join("settings.json")).unwrap_or_default();
        let blg_status = collector::freeze_logman(
            root,
            &evidence,
            &settings,
            monitoring.load(Ordering::Relaxed),
        );
        if incident_cancelled(&cancellation) {
            return Ok(());
        }
        let _ = fs::write(evidence.join("performance-status.txt"), blg_status);
        collector::export_event_logs(&evidence, start, end);
        if incident_cancelled(&cancellation) {
            return Ok(());
        }

        incident.status = "extracting".into();
        write_json(&dir.join("incident.json"), &incident)?;
        let system_events = fs::read_to_string(evidence.join("system.xml")).unwrap_or_default();
        let application_events =
            fs::read_to_string(evidence.join("application.xml")).unwrap_or_default();
        let observations =
            analysis::extract(&samples, trigger, &system_events, &application_events);
        if incident_cancelled(&cancellation) {
            return Ok(());
        }
        write_json(&dir.join("extracted/facts.json"), &observations)?;
        storage::replace_observations(root, id, &observations)?;
        incident.status = "ready_for_analysis".into();
        write_json(&dir.join("incident.json"), &incident)?;
        storage::upsert_incident(root, &incident)?;
        storage::audit(root, "incident.ready_for_analysis", Some(id), None)?;
        enforce_incident_retention(root, &settings)
    })();
    if let Err(error) = result {
        if incident_cancelled(&cancellation) || !dir.is_dir() {
            return;
        }
        if let Ok(mut incident) = read_json::<Incident>(&dir.join("incident.json")) {
            incident.status = "failed".into();
            let _ = write_json(&dir.join("incident.json"), &incident);
            let _ = storage::upsert_incident(root, &incident);
        }
        let _ = fs::write(dir.join("pipeline-error.txt"), &error);
        let _ = storage::audit(root, "incident.pipeline_failed", Some(id), Some(&error));
    }
}

fn enforce_incident_retention(root: &Path, settings: &Settings) -> Result<(), String> {
    let incidents = root.join("incidents");
    let now = Utc::now();
    let mut candidates = Vec::new();
    for entry in fs::read_dir(&incidents)
        .map_err(|error| error.to_string())?
        .flatten()
    {
        let path = entry.path();
        if !path.is_dir() || path.join(".pinned").exists() {
            continue;
        }
        let incident: Incident = match read_json(&path.join("incident.json")) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if matches!(
            incident.status.as_str(),
            "capturing" | "freezing" | "extracting" | "analyzing"
        ) {
            continue;
        }
        let created = collector::parse_time(&incident.created_at)?;
        if settings.retention_days > 0
            && now.signed_duration_since(created).num_days() >= settings.retention_days as i64
        {
            fs::remove_dir_all(&path).map_err(|error| error.to_string())?;
            storage::delete_incident(root, &incident.id)?;
            storage::audit(
                root,
                "retention.expired",
                Some(&incident.id),
                Some("retention days exceeded"),
            )?;
        } else {
            candidates.push((created, incident.id, path));
        }
    }
    candidates.sort_by_key(|item| item.0);
    let quota = settings.incident_limit_gb * 1_073_741_824;
    let mut total = dir_size(&incidents);
    for (_, id, path) in candidates {
        if total <= quota {
            break;
        }
        let size = dir_size(&path);
        fs::remove_dir_all(&path).map_err(|error| error.to_string())?;
        storage::delete_incident(root, &id)?;
        storage::audit(
            root,
            "retention.quota_deleted",
            Some(&id),
            Some("incident storage quota exceeded"),
        )?;
        total = total.saturating_sub(size);
    }
    Ok(())
}

fn quick_incident(app: &tauri::AppHandle, symptom: &str, severity: &str, trigger_source: &str) {
    let state = app.state::<AppState>();
    let latest = state.latest.lock().unwrap().clone();
    let draft = IncidentDraft {
        symptom: symptom.into(),
        severity: severity.into(),
        duration_seconds: 0,
        still_happening: false,
        description: "通过全局快捷键或系统托盘快速标记".into(),
    };
    let _ = create_incident_internal(
        &state.root,
        &latest,
        draft,
        None,
        trigger_source,
        IncidentRuntime {
            io_lock: state.io_lock.clone(),
            monitoring: state.monitoring.clone(),
            cancellations: state.incident_cancellations.clone(),
        },
    );
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .setup(|app| {
            let root = app.path().app_data_dir()?;
            fs::create_dir_all(root.join("incidents"))?;
            fs::create_dir_all(root.join("rolling"))?;
            if !root.join("settings.json").exists() {
                write_json(&root.join("settings.json"), &Settings::default())
                    .map_err(std::io::Error::other)?;
            }
            storage::initialize(&root).map_err(std::io::Error::other)?;
            let removed_unsupported =
                discard_unsupported_incidents(&root).map_err(std::io::Error::other)?;
            if removed_unsupported > 0 {
                storage::audit(
                    &root,
                    "schema.unsupported_incidents_discarded",
                    None,
                    Some(&removed_unsupported.to_string()),
                )
                .map_err(std::io::Error::other)?;
            }
            let settings: Settings = read_json(&root.join("settings.json")).unwrap_or_default();
            enforce_incident_retention(&root, &settings).map_err(std::io::Error::other)?;
            let monitoring = Arc::new(AtomicBool::new(true));
            let latest = Arc::new(Mutex::new(collector::Sample::default()));
            let io_lock = Arc::new(Mutex::new(()));
            let incident_cancellations = Arc::new(Mutex::new(HashMap::new()));
            let previous_session: Option<serde_json::Value> =
                read_json(&root.join("session.lock")).ok();
            let recovery = previous_session.map(|value| RecoveryCandidate {
                detected_at: Utc::now().to_rfc3339(),
                previous_session_started_at: value
                    .get("started_at")
                    .and_then(|value| value.as_str())
                    .unwrap_or("未知")
                    .into(),
                last_sample_at: value
                    .get("last_sample_at")
                    .and_then(|value| value.as_str())
                    .map(str::to_owned),
            });
            write_json(
                &root.join("session.lock"),
                &serde_json::json!({
                    "started_at": Utc::now().to_rfc3339(),
                    "last_sample_at": null
                }),
            )
            .map_err(std::io::Error::other)?;
            collector::spawn(
                root.clone(),
                monitoring.clone(),
                latest.clone(),
                io_lock.clone(),
            );
            let logman_status = collector::start_logman(
                &root,
                settings.sample_interval_seconds,
                settings.rolling_limit_gb * 768,
            );
            app.manage(AppState {
                root,
                started: Instant::now(),
                monitoring,
                latest,
                logman_status: Mutex::new(logman_status),
                recovery: Mutex::new(recovery),
                io_lock,
                incident_cancellations,
                shortcut_status: Mutex::new("正在注册".into()),
            });

            let shortcut_status = match app.global_shortcut().on_shortcut(
                "Ctrl+Shift+F12",
                |app, _shortcut, event| {
                    if event.state == ShortcutState::Pressed {
                        quick_incident(app, "system_freeze", "high", "shortcut");
                    }
                },
            ) {
                Ok(()) => "Ctrl + Shift + F12 已启用".into(),
                Err(error) => format!("快捷键不可用：{error}"),
            };
            *app.state::<AppState>()
                .shortcut_status
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = shortcut_status;

            let show = MenuItem::with_id(app, "show", "打开系统黑盒子", true, None::<&str>)?;
            let mark = MenuItem::with_id(app, "mark", "立即标记事故", true, None::<&str>)?;
            let freeze = MenuItem::with_id(app, "freeze", "系统卡死 / 无响应", true, None::<&str>)?;
            let network = MenuItem::with_id(app, "network", "网络缓慢", true, None::<&str>)?;
            let app_hang = MenuItem::with_id(app, "app_hang", "程序无响应", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "退出并停止监控", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &mark, &freeze, &network, &app_hang, &quit])?;
            TrayIconBuilder::new()
                .icon(app.default_window_icon().expect("default icon").clone())
                .tooltip("系统黑盒子 · 监控正在运行")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "mark" | "freeze" => quick_incident(app, "system_freeze", "high", "tray"),
                    "network" => quick_incident(app, "network_slow", "medium", "tray"),
                    "app_hang" => quick_incident(app, "app_hang", "medium", "tray"),
                    "quit" => {
                        collector::stop_logman();
                        let state = app.state::<AppState>();
                        let _ = fs::remove_file(state.root.join("session.lock"));
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        if let Some(window) = tray.app_handle().get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_settings,
            save_settings,
            list_incidents,
            get_dashboard,
            get_diagnostic_capabilities,
            set_monitoring,
            create_incident,
            get_incident,
            analyze_incident,
            delete_incident,
            set_incident_pinned,
            delete_all_incidents,
            delete_all_data,
            get_recovery_candidate,
            resolve_recovery
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application");
    app.run(|app_handle, event| {
        if matches!(event, tauri::RunEvent::Exit) {
            let state = app_handle.state::<AppState>();
            state.monitoring.store(false, Ordering::Relaxed);
            collector::stop_logman();
            let _guard = state
                .io_lock
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let _ = fs::remove_file(state.root.join("session.lock"));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("blackbox-test-{}", Uuid::new_v4()));
            fs::create_dir_all(path.join("incidents")).unwrap();
            storage::initialize(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn add_incident(root: &Path, id: &str, age_days: i64, pinned: bool) {
        let incident = Incident {
            schema_version: INCIDENT_SCHEMA_VERSION,
            id: id.into(),
            created_at: (Utc::now() - ChronoDuration::days(age_days)).to_rfc3339(),
            trigger_time: Utc::now().to_rfc3339(),
            trigger_source: "test".into(),
            symptom: "system_freeze".into(),
            symptom_label: "系统无响应".into(),
            severity: "high".into(),
            status: "completed".into(),
            pre_window_seconds: 600,
            post_window_seconds: 120,
            likely_cause: None,
            confidence: None,
            sensitivity_level: 1,
            machine_id: "test-machine".into(),
            app_version: "0.1.0".into(),
        };
        let directory = root.join("incidents").join(id);
        write_json(&directory.join("incident.json"), &incident).unwrap();
        fs::write(directory.join("evidence.bin"), vec![0; 512]).unwrap();
        if pinned {
            fs::write(directory.join(".pinned"), b"pinned").unwrap();
        }
        storage::upsert_incident(root, &incident).unwrap();
    }

    #[test]
    fn retention_keeps_pinned_incidents() {
        let root = TestDirectory::new();
        add_incident(&root.0, "expired", 31, false);
        add_incident(&root.0, "pinned", 31, true);
        enforce_incident_retention(&root.0, &Settings::default()).unwrap();
        assert!(!root.0.join("incidents/expired").exists());
        assert!(root.0.join("incidents/pinned").exists());
    }

    #[test]
    fn collection_summary_uses_actual_samples_and_filtered_events() {
        let root = TestDirectory::new();
        add_incident(&root.0, "summary", 0, false);
        let directory = root.0.join("incidents/summary");
        fs::create_dir_all(directory.join("evidence")).unwrap();
        let incident: Incident = read_json(&directory.join("incident.json")).unwrap();
        let trigger_ms = chrono::DateTime::parse_from_rfc3339(&incident.trigger_time)
            .unwrap()
            .timestamp_millis();
        let mut samples = [
            collector::Sample {
                timestamp_ms: trigger_ms - 30_000,
                timestamp: incident.trigger_time.clone(),
                effective_interval_seconds: 2,
                ..Default::default()
            },
            collector::Sample {
                timestamp_ms: trigger_ms + 10_000,
                timestamp: incident.trigger_time.clone(),
                effective_interval_seconds: 2,
                ..Default::default()
            },
        ];
        samples[0].cpu_percent = 92.0;
        samples[0].top_processes = vec![collector::ProcessSample {
            pid: 42,
            name: "load.exe".into(),
            cpu_percent: 88.0,
            memory_bytes: 512 * 1024 * 1024,
            disk_write_bytes_per_sec: 4 * 1024 * 1024,
            ..Default::default()
        }];
        fs::write(
            directory.join("evidence/metrics.jsonl"),
            samples
                .iter()
                .map(|sample| serde_json::to_string(sample).unwrap())
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .unwrap();
        fs::write(
            directory.join("evidence/system.xml"),
            "<Events><Event><System><Provider Name=\"Disk\"/><EventID>153</EventID><Level>2</Level><TimeCreated SystemTime=\"2026-01-01T00:00:00Z\"/></System><RenderingInfo><Message>存储请求重试。</Message></RenderingInfo></Event><Event><System /></Event></Events>",
        )
        .unwrap();
        fs::write(
            directory.join("evidence/application.xml"),
            "<Events><Event><System /></Event></Events>",
        )
        .unwrap();
        let raw_files = [
            "evidence/metrics.jsonl",
            "evidence/system.xml",
            "evidence/application.xml",
        ]
        .into_iter()
        .map(|name| RawFile {
            name: name.into(),
            kind: "test".into(),
            size_bytes: fs::metadata(directory.join(name)).unwrap().len(),
        })
        .collect::<Vec<_>>();

        let summary = build_collection(&directory, &incident, &samples, &[], &None, &raw_files);

        assert_eq!(summary.sample_count, 2);
        assert_eq!(summary.event_count, 3);
        assert_eq!(summary.actual_coverage, "−30 秒 至 +10 秒");
        assert_eq!(summary.sensitivity_level, 2);

        let diagnostics = build_diagnostics(&directory, &incident, &samples);
        assert_eq!(diagnostics.points.len(), 2);
        assert_eq!(diagnostics.processes.len(), 1);
        assert_eq!(diagnostics.processes[0].name, "load.exe");
        assert_eq!(diagnostics.events.len(), 3);
        assert_eq!(diagnostics.events[0].provider, "Disk");
        assert!(diagnostics
            .highlights
            .iter()
            .any(|highlight| highlight.label == "CPU 峰值"));
    }

    #[test]
    fn cancelled_capture_does_not_recreate_deleted_incident() {
        let root = TestDirectory::new();
        add_incident(&root.0, "pending", 0, false);
        let manifest = root.0.join("incidents/pending/incident.json");
        let mut incident: Incident = read_json(&manifest).unwrap();
        incident.status = "capturing".into();
        incident.trigger_time = Utc::now().to_rfc3339();
        incident.post_window_seconds = 10;
        write_json(&manifest, &incident).unwrap();

        let cancellation = Arc::new(AtomicBool::new(false));
        let io_lock = Arc::new(Mutex::new(()));
        let worker_root = root.0.clone();
        let worker_cancellation = cancellation.clone();
        let worker_lock = io_lock.clone();
        let handle = thread::spawn(move || {
            finalize_incident(
                &worker_root,
                "pending",
                worker_lock,
                Arc::new(AtomicBool::new(false)),
                worker_cancellation,
            )
        });

        thread::sleep(Duration::from_millis(50));
        cancellation.store(true, Ordering::Release);
        {
            let _guard = io_lock.lock().unwrap();
            fs::remove_dir_all(root.0.join("incidents/pending")).unwrap();
            storage::delete_incident(&root.0, "pending").unwrap();
        }
        handle.join().unwrap();

        assert!(!root.0.join("incidents/pending").exists());
    }

    #[test]
    fn retention_does_not_delete_active_capture() {
        let root = TestDirectory::new();
        add_incident(&root.0, "pending", 31, false);
        let manifest = root.0.join("incidents/pending/incident.json");
        let mut incident: Incident = read_json(&manifest).unwrap();
        incident.status = "capturing".into();
        write_json(&manifest, &incident).unwrap();

        enforce_incident_retention(&root.0, &Settings::default()).unwrap();
        assert!(root.0.join("incidents/pending").exists());
    }

    #[test]
    fn quota_deletes_oldest_unpinned_incident() {
        let root = TestDirectory::new();
        add_incident(&root.0, "old", 2, false);
        add_incident(&root.0, "new", 1, false);
        add_incident(&root.0, "pinned", 3, true);
        let settings = Settings {
            retention_days: 0,
            incident_limit_gb: 0,
            ..Default::default()
        };
        enforce_incident_retention(&root.0, &settings).unwrap();
        assert!(!root.0.join("incidents/old").exists());
        assert!(!root.0.join("incidents/new").exists());
        assert!(root.0.join("incidents/pinned").exists());
    }

    #[test]
    fn rejects_remote_ai_and_unsafe_dump_settings() {
        let remote = Settings {
            ai_mode: "ollama".into(),
            ollama_endpoint: "https://example.com".into(),
            ..Default::default()
        };
        assert!(validate_settings(&remote).is_err());
        let dumps = Settings {
            dumps_enabled: true,
            ..Default::default()
        };
        assert!(validate_settings(&dumps).is_err());
        let invalid_draft = IncidentDraft {
            symptom: "arbitrary".into(),
            severity: "high".into(),
            duration_seconds: 1,
            still_happening: false,
            description: String::new(),
        };
        assert!(validate_incident_draft(&invalid_draft).is_err());
    }

    #[test]
    fn incident_manifest_contains_required_versioned_fields() {
        let root = TestDirectory::new();
        add_incident(&root.0, "manifest", 0, false);
        let value: serde_json::Value =
            read_json(&root.0.join("incidents/manifest/incident.json")).unwrap();
        assert_eq!(value["schema_version"], INCIDENT_SCHEMA_VERSION);
        assert_eq!(value["trigger_source"], "test");
        assert_eq!(value["machine_id"], "test-machine");
        assert_eq!(value["app_version"], "0.1.0");
    }

    #[test]
    fn unsupported_incident_directories_are_discarded_without_migration() {
        let root = TestDirectory::new();
        let legacy = root.0.join("incidents/legacy");
        let old_version = root.0.join("incidents/old-version");
        write_json(
            &legacy.join("incident.json"),
            &serde_json::json!({ "id": "legacy", "trigger_time": "2026-01-01T00:00:00Z" }),
        )
        .unwrap();
        write_json(
            &old_version.join("incident.json"),
            &serde_json::json!({
                "schema_version": 1,
                "id": "old-version",
                "trigger_time": "2026-01-01T00:00:00Z"
            }),
        )
        .unwrap();
        add_incident(&root.0, "current", 0, false);

        assert_eq!(discard_unsupported_incidents(&root.0).unwrap(), 2);
        assert!(!legacy.exists());
        assert!(!old_version.exists());
        assert!(root.0.join("incidents/current").exists());
    }
}
