use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use sysinfo::{Networks, ProcessesToUpdate, System};

use crate::{read_json, Settings};

const SEGMENT_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub(crate) struct Sample {
    pub timestamp: String,
    pub timestamp_ms: i64,
    pub cpu_percent: f32,
    pub memory_percent: f64,
    pub available_memory_bytes: u64,
    pub commit_percent: f64,
    pub disk_read_bytes_per_sec: u64,
    pub disk_write_bytes_per_sec: u64,
    pub disk_latency_ms: f64,
    pub disk_queue_length: f64,
    pub network_bytes_per_sec: u64,
    pub network_errors: u64,
    pub network_discards: u64,
    pub top_process: Option<String>,
    pub top_process_cpu_percent: f32,
    pub blackbox_cpu_percent: f32,
    pub blackbox_memory_bytes: u64,
    pub blackbox_disk_write_bytes_per_sec: u64,
    pub effective_interval_seconds: u64,
}

pub(crate) fn spawn(
    root: PathBuf,
    enabled: Arc<AtomicBool>,
    latest: Arc<Mutex<Sample>>,
    io_lock: Arc<Mutex<()>>,
) {
    thread::Builder::new()
        .name("blackbox-rolling-collector".into())
        .spawn(move || {
            let mut system = System::new_all();
            let mut networks = Networks::new_with_refreshed_list();
            let mut windows_metrics = WindowsMetrics::new();
            let mut effective_interval = 2;
            loop {
                let settings: Settings = read_json(&root.join("settings.json")).unwrap_or_default();
                effective_interval = effective_interval.max(settings.sample_interval_seconds);
                if enabled.load(Ordering::Relaxed) {
                    system.refresh_cpu_usage();
                    system.refresh_memory();
                    system.refresh_processes(ProcessesToUpdate::All, true);
                    networks.refresh(true);

                    let disk_read: u64 = system
                        .processes()
                        .values()
                        .map(|p| p.disk_usage().read_bytes)
                        .sum();
                    let disk_write: u64 = system
                        .processes()
                        .values()
                        .map(|p| p.disk_usage().written_bytes)
                        .sum();
                    let network: u64 = networks
                        .values()
                        .map(|data| data.received() + data.transmitted())
                        .sum();
                    let top = system.processes().values().max_by(|a, b| {
                        a.cpu_usage()
                            .partial_cmp(&b.cpu_usage())
                            .unwrap_or(std::cmp::Ordering::Equal)
                    });
                    let own_process = sysinfo::get_current_pid()
                        .ok()
                        .and_then(|pid| system.process(pid));
                    let total_memory = system.total_memory();
                    let used_memory = system.used_memory();
                    let platform = windows_metrics.sample();
                    let now = Utc::now();
                    let sample = Sample {
                        timestamp: now.to_rfc3339(),
                        timestamp_ms: now.timestamp_millis(),
                        cpu_percent: system.global_cpu_usage(),
                        memory_percent: if total_memory == 0 {
                            0.0
                        } else {
                            used_memory as f64 / total_memory as f64 * 100.0
                        },
                        available_memory_bytes: total_memory.saturating_sub(used_memory),
                        commit_percent: platform.commit_percent,
                        disk_read_bytes_per_sec: disk_read / effective_interval.max(1),
                        disk_write_bytes_per_sec: disk_write / effective_interval.max(1),
                        disk_latency_ms: platform.disk_latency_ms,
                        disk_queue_length: platform.disk_queue_length,
                        network_bytes_per_sec: network / effective_interval.max(1),
                        network_errors: platform.network_errors,
                        network_discards: platform.network_discards,
                        top_process: top.map(|p| p.name().to_string_lossy().into_owned()),
                        top_process_cpu_percent: top.map(|p| p.cpu_usage()).unwrap_or(0.0),
                        blackbox_cpu_percent: own_process
                            .map(|process| process.cpu_usage())
                            .unwrap_or(0.0),
                        blackbox_memory_bytes: own_process
                            .map(|process| process.memory())
                            .unwrap_or(0),
                        blackbox_disk_write_bytes_per_sec: own_process
                            .map(|process| process.disk_usage().written_bytes)
                            .unwrap_or(0)
                            / effective_interval.max(1),
                        effective_interval_seconds: effective_interval,
                    };
                    effective_interval = budgeted_interval(
                        settings.sample_interval_seconds,
                        sample.blackbox_cpu_percent,
                    );
                    let write_result = {
                        let _guard = io_lock.lock().unwrap_or_else(|error| error.into_inner());
                        let result = append_sample(&root, &sample);
                        if result.is_ok() {
                            enforce_quota(
                                &root.join("rolling"),
                                settings.rolling_limit_gb * 268_435_456,
                            );
                        }
                        result
                    };
                    if write_result.is_ok() {
                        update_session_marker(&root, &sample.timestamp);
                        if let Ok(mut value) = latest.lock() {
                            *value = sample;
                        }
                    }
                }
                thread::sleep(Duration::from_secs(effective_interval.max(1)));
            }
        })
        .expect("failed to start rolling collector");
}

fn budgeted_interval(requested: u64, self_cpu_percent: f32) -> u64 {
    if self_cpu_percent >= 10.0 {
        requested.max(10)
    } else if self_cpu_percent >= 5.0 {
        requested.max(5)
    } else {
        requested
    }
}

#[derive(Default)]
struct PlatformMetrics {
    commit_percent: f64,
    disk_latency_ms: f64,
    disk_queue_length: f64,
    network_errors: u64,
    network_discards: u64,
}

#[cfg(target_os = "windows")]
struct WindowsMetrics {
    query: windows::Win32::System::Performance::PDH_HQUERY,
    latency: windows::Win32::System::Performance::PDH_HCOUNTER,
    queue: windows::Win32::System::Performance::PDH_HCOUNTER,
    previous_errors: u64,
    previous_discards: u64,
    network_initialized: bool,
}

#[cfg(target_os = "windows")]
impl WindowsMetrics {
    fn new() -> Option<Self> {
        use windows::{
            core::w,
            Win32::System::Performance::{
                PdhAddEnglishCounterW, PdhCollectQueryData, PdhOpenQueryW, PDH_HCOUNTER, PDH_HQUERY,
            },
        };
        unsafe {
            let mut query = PDH_HQUERY::default();
            let mut latency = PDH_HCOUNTER::default();
            let mut queue = PDH_HCOUNTER::default();
            if PdhOpenQueryW(None, 0, &mut query) != 0
                || PdhAddEnglishCounterW(
                    query,
                    w!(r"\PhysicalDisk(_Total)\Avg. Disk sec/Transfer"),
                    0,
                    &mut latency,
                ) != 0
                || PdhAddEnglishCounterW(
                    query,
                    w!(r"\PhysicalDisk(_Total)\Current Disk Queue Length"),
                    0,
                    &mut queue,
                ) != 0
            {
                return None;
            }
            let _ = PdhCollectQueryData(query);
            Some(Self {
                query,
                latency,
                queue,
                previous_errors: 0,
                previous_discards: 0,
                network_initialized: false,
            })
        }
    }

    fn sample(&mut self) -> PlatformMetrics {
        use windows::Win32::{
            NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2},
            System::{
                Performance::{
                    PdhCollectQueryData, PdhGetFormattedCounterValue, PDH_FMT_COUNTERVALUE,
                    PDH_FMT_DOUBLE,
                },
                SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX},
            },
        };
        unsafe {
            let _ = PdhCollectQueryData(self.query);
            let counter_value = |counter| {
                let mut value = PDH_FMT_COUNTERVALUE::default();
                if PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, None, &mut value) == 0 {
                    let result = value.Anonymous.doubleValue;
                    if value.CStatus <= 1 && result.is_finite() && result >= 0.0 {
                        result
                    } else {
                        0.0
                    }
                } else {
                    0.0
                }
            };
            let mut memory = MEMORYSTATUSEX {
                dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
                ..Default::default()
            };
            let commit_percent =
                if GlobalMemoryStatusEx(&mut memory).is_ok() && memory.ullTotalPageFile > 0 {
                    (memory.ullTotalPageFile - memory.ullAvailPageFile) as f64
                        / memory.ullTotalPageFile as f64
                        * 100.0
                } else {
                    0.0
                };

            let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
            let (total_errors, total_discards, network_valid) =
                if GetIfTable2(&mut table).is_ok() && !table.is_null() {
                    let rows = std::slice::from_raw_parts(
                        (*table).Table.as_ptr(),
                        (*table).NumEntries as usize,
                    );
                    let totals = rows.iter().fold((0u64, 0u64), |value, row| {
                        (
                            value.0 + row.InErrors + row.OutErrors,
                            value.1 + row.InDiscards + row.OutDiscards,
                        )
                    });
                    FreeMibTable(table.cast());
                    (totals.0, totals.1, true)
                } else {
                    (0, 0, false)
                };
            let network_errors = if self.network_initialized && network_valid {
                total_errors.saturating_sub(self.previous_errors)
            } else {
                0
            };
            let network_discards = if self.network_initialized && network_valid {
                total_discards.saturating_sub(self.previous_discards)
            } else {
                0
            };
            if network_valid {
                self.previous_errors = total_errors;
                self.previous_discards = total_discards;
                self.network_initialized = true;
            }
            PlatformMetrics {
                commit_percent,
                disk_latency_ms: counter_value(self.latency) * 1000.0,
                disk_queue_length: counter_value(self.queue),
                network_errors,
                network_discards,
            }
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for WindowsMetrics {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::System::Performance::PdhCloseQuery(self.query);
        }
    }
}

#[cfg(not(target_os = "windows"))]
struct WindowsMetrics;

#[cfg(not(target_os = "windows"))]
impl WindowsMetrics {
    fn new() -> Option<Self> {
        None
    }
    fn sample(&mut self) -> PlatformMetrics {
        PlatformMetrics::default()
    }
}

trait PlatformSampler {
    fn sample(&mut self) -> PlatformMetrics;
}

impl PlatformSampler for Option<WindowsMetrics> {
    fn sample(&mut self) -> PlatformMetrics {
        self.as_mut()
            .map(WindowsMetrics::sample)
            .unwrap_or_default()
    }
}

fn update_session_marker(root: &Path, last_sample_at: &str) {
    let path = root.join("session.lock");
    let mut marker: serde_json::Value = fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_else(|| serde_json::json!({ "started_at": Utc::now().to_rfc3339() }));
    marker["last_sample_at"] = serde_json::Value::String(last_sample_at.into());
    if let Ok(bytes) = serde_json::to_vec_pretty(&marker) {
        let _ = fs::write(path, bytes);
    }
}

fn append_sample(root: &Path, sample: &Sample) -> Result<(), String> {
    let dir = root.join("rolling");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut files = segment_files(&dir);
    let path = files
        .pop()
        .filter(|p| {
            fs::metadata(p)
                .map(|m| m.len() < SEGMENT_BYTES)
                .unwrap_or(false)
        })
        .unwrap_or_else(|| {
            dir.join(format!(
                "metrics_{}.jsonl",
                Utc::now().format("%Y%m%d_%H%M%S")
            ))
        });
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, sample).map_err(|e| e.to_string())?;
    writer.write_all(b"\n").map_err(|e| e.to_string())
}

fn segment_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<_> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .collect();
    files.sort();
    files
}

fn enforce_quota(dir: &Path, quota: u64) {
    let files = segment_files(dir);
    let mut total: u64 = files
        .iter()
        .map(|p| fs::metadata(p).map(|m| m.len()).unwrap_or(0))
        .sum();
    for file in files {
        if total <= quota {
            break;
        }
        let size = fs::metadata(&file).map(|m| m.len()).unwrap_or(0);
        if fs::remove_file(file).is_ok() {
            total = total.saturating_sub(size);
        }
    }
}

pub(crate) fn freeze_window(
    root: &Path,
    destination: &Path,
    start_ms: i64,
    end_ms: i64,
) -> Result<Vec<Sample>, String> {
    fs::create_dir_all(destination).map_err(|e| e.to_string())?;
    let output = File::create(destination.join("metrics.jsonl")).map_err(|e| e.to_string())?;
    let mut writer = BufWriter::new(output);
    let mut samples = Vec::new();
    for path in segment_files(&root.join("rolling")) {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(_) => continue,
        };
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            if let Ok(sample) = serde_json::from_str::<Sample>(&line) {
                if sample.timestamp_ms >= start_ms && sample.timestamp_ms <= end_ms {
                    serde_json::to_writer(&mut writer, &sample).map_err(|e| e.to_string())?;
                    writer.write_all(b"\n").map_err(|e| e.to_string())?;
                    samples.push(sample);
                }
            }
        }
    }
    Ok(samples)
}

pub(crate) fn export_event_logs(
    destination: &Path,
    window_start_ms: i64,
    window_end_ms: i64,
) -> Vec<String> {
    let mut errors = Vec::new();
    if fs::create_dir_all(destination).is_err() {
        return vec!["无法创建事件日志目录".into()];
    }
    #[cfg(target_os = "windows")]
    for channel in ["System", "Application"] {
        let evtx = destination.join(format!("{}.evtx", channel.to_lowercase()));
        let now = Utc::now().timestamp_millis();
        let minimum_age = now.saturating_sub(window_end_ms).max(0);
        let maximum_age = now.saturating_sub(window_start_ms).max(minimum_age);
        let time_query = format!(
            "*[System[TimeCreated[timediff(@SystemTime) >= {minimum_age} and timediff(@SystemTime) <= {maximum_age}]]]"
        );
        let query_arg = format!("/q:{time_query}");
        let output = Command::new("wevtutil")
            .args(["epl", channel])
            .arg(&evtx)
            .args([&query_arg, "/ow:true"])
            .output();
        match output {
            Ok(result) if result.status.success() => {}
            Ok(result) => errors.push(format!(
                "{channel}: {}",
                String::from_utf8_lossy(&result.stderr).trim()
            )),
            Err(error) => errors.push(format!("{channel}: {error}")),
        }

        let provider_filter = if channel == "System" {
            "(Level=1 or Level=2 or Provider[@Name='Microsoft-Windows-Kernel-Power'] or Provider[@Name='Microsoft-Windows-WHEA-Logger'] or Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'] or Provider[@Name='Disk'] or Provider[@Name='Ntfs'] or Provider[@Name='storport'] or Provider[@Name='stornvme'] or Provider[@Name='Display'] or Provider[@Name='Microsoft-Windows-DNS-Client'] or Provider[@Name='Microsoft-Windows-NetworkProfile'])"
        } else {
            "(Level=1 or Level=2 or Provider[@Name='Application Hang'] or Provider[@Name='Application Error'])"
        };
        let query = format!(
            "*[System[TimeCreated[timediff(@SystemTime) >= {minimum_age} and timediff(@SystemTime) <= {maximum_age}] and {provider_filter}]]"
        );
        let xml = destination.join(format!("{}.xml", channel.to_lowercase()));
        let query_arg = format!("/q:{query}");
        match Command::new("wevtutil")
            .args(["qe", channel, &query_arg, "/rd:true", "/f:xml", "/c:200"])
            .output()
        {
            Ok(result) if result.status.success() => {
                let _ = fs::write(xml, result.stdout);
            }
            Ok(result) => errors.push(format!(
                "{channel} XML: {}",
                String::from_utf8_lossy(&result.stderr).trim()
            )),
            Err(error) => errors.push(format!("{channel} XML: {error}")),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (window_start_ms, window_end_ms);
        errors.push("Windows Event Log 仅在 Windows 上可用".into());
    }
    if !errors.is_empty() {
        let _ = fs::write(destination.join("export-errors.txt"), errors.join("\n"));
    }
    errors
}

pub(crate) fn start_logman(root: &Path, interval: u64, limit_mb: u64) -> String {
    #[cfg(target_os = "windows")]
    {
        let dir = root.join("rolling");
        let _ = fs::create_dir_all(&dir);
        let output = dir.join("performance");
        let _ = Command::new("logman")
            .args(["stop", "SystemBlackBox", "-ets"])
            .output();
        let _ = Command::new("logman")
            .args(["delete", "SystemBlackBox"])
            .output();
        let interval = format!("00:00:{:02}", interval.clamp(1, 59));
        let limit = limit_mb.max(64).to_string();
        let result = Command::new("logman")
            .args([
                "create",
                "counter",
                "SystemBlackBox",
                "-c",
                r"\Processor(_Total)\% Processor Time",
                r"\Memory\Available MBytes",
                r"\PhysicalDisk(_Total)\Avg. Disk sec/Transfer",
                r"\PhysicalDisk(_Total)\Current Disk Queue Length",
                r"\Network Interface(*)\Bytes Total/sec",
                "-si",
                &interval,
                "-f",
                "bincirc",
                "-max",
                &limit,
                "-o",
            ])
            .arg(output)
            .output();
        match result {
            Ok(value) if value.status.success() => {
                match Command::new("logman")
                    .args(["start", "SystemBlackBox", "-ets"])
                    .output()
                {
                    Ok(value) if value.status.success() => "运行中（logman 循环 BLG）".into(),
                    Ok(value) => format!(
                        "降级：logman 启动失败（{}）",
                        String::from_utf8_lossy(&value.stderr).trim()
                    ),
                    Err(error) => format!("降级：无法启动 logman（{error}）"),
                }
            }
            Ok(value) => format!(
                "降级：logman 配置失败（{}）",
                String::from_utf8_lossy(&value.stderr).trim()
            ),
            Err(error) => format!("降级：logman 不可用（{error}）"),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (root, interval, limit_mb);
        "不可用：非 Windows 平台".into()
    }
}

pub(crate) fn stop_logman() {
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("logman")
            .args(["stop", "SystemBlackBox", "-ets"])
            .output();
    }
}

pub(crate) fn freeze_logman(
    root: &Path,
    destination: &Path,
    settings: &crate::Settings,
    restart: bool,
) -> String {
    stop_logman();
    let rolling = root.join("rolling");
    let mut blg_files: Vec<_> = fs::read_dir(&rolling)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "blg"))
        .collect();
    blg_files.sort();
    let result = if let Some(source) = blg_files.pop() {
        fs::create_dir_all(destination)
            .and_then(|_| fs::copy(source, destination.join("performance.blg")).map(|_| ()))
            .map(|_| "BLG 事故窗口已冻结".to_owned())
            .unwrap_or_else(|error| format!("BLG 复制失败：{error}"))
    } else {
        "未找到 logman BLG；结构化 JSONL 证据仍可用".into()
    };
    if restart {
        let _ = start_logman(
            root,
            settings.sample_interval_seconds,
            settings.rolling_limit_gb * 768,
        );
    }
    result
}

pub(crate) fn parse_time(value: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("blackbox-test-{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn freezes_only_samples_inside_incident_window() {
        let root = TestDirectory::new();
        for timestamp_ms in [1_000, 2_000, 3_000] {
            append_sample(
                &root.0,
                &Sample {
                    timestamp: timestamp_ms.to_string(),
                    timestamp_ms,
                    ..Default::default()
                },
            )
            .unwrap();
        }
        let destination = root.0.join("incident/evidence");
        let samples = freeze_window(&root.0, &destination, 1_500, 2_500).unwrap();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].timestamp_ms, 2_000);
        assert!(destination.join("metrics.jsonl").is_file());
    }

    #[test]
    fn resource_budget_only_reduces_sampling_frequency() {
        assert_eq!(budgeted_interval(2, 4.9), 2);
        assert_eq!(budgeted_interval(2, 5.0), 5);
        assert_eq!(budgeted_interval(2, 10.0), 10);
        assert_eq!(budgeted_interval(10, 6.0), 10);
    }
}
