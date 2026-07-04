use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use crate::Settings;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct Capability {
    pub id: String,
    pub name: String,
    pub category: String,
    pub status: String,
    pub required_now: bool,
    pub usage: String,
    pub detail: String,
    pub path: Option<String>,
    pub version: Option<String>,
    pub requires_admin: bool,
    pub recommendation: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct CapabilityReport {
    pub checked_at: String,
    pub is_elevated: bool,
    pub available: usize,
    pub attention: usize,
    pub capabilities: Vec<Capability>,
}

fn capability(
    id: &str,
    name: &str,
    category: &str,
    status: &str,
    required_now: bool,
    usage: &str,
    detail: impl Into<String>,
) -> Capability {
    Capability {
        id: id.into(),
        name: name.into(),
        category: category.into(),
        status: status.into(),
        required_now,
        usage: usage.into(),
        detail: detail.into(),
        path: None,
        version: None,
        requires_admin: false,
        recommendation: None,
    }
}

#[cfg(target_os = "windows")]
fn is_elevated() -> bool {
    unsafe { windows::Win32::UI::Shell::IsUserAnAdmin().as_bool() }
}

#[cfg(not(target_os = "windows"))]
fn is_elevated() -> bool {
    false
}

fn system_tool(name: &str) -> PathBuf {
    PathBuf::from(env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()))
        .join("System32")
        .join(name)
}

#[cfg(target_os = "windows")]
fn run_probe(path: &Path, args: &[&str]) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    let output = Command::new(path)
        .args(args)
        .creation_flags(0x0800_0000)
        .output()
        .map_err(|error| error.to_string())?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = [stdout.trim(), stderr.trim()]
        .into_iter()
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join("；");
    if output.status.success() {
        Ok(detail)
    } else {
        Err(if detail.is_empty() {
            format!("退出状态 {}", output.status)
        } else {
            detail
        })
    }
}

#[cfg(not(target_os = "windows"))]
fn run_probe(_path: &Path, _args: &[&str]) -> Result<String, String> {
    Err("当前平台不是 Windows".into())
}

struct ExecutableSpec<'a> {
    id: &'a str,
    name: &'a str,
    category: &'a str,
    required_now: bool,
    usage: &'a str,
    path: PathBuf,
    probe_args: Option<&'a [&'a str]>,
    requires_admin: bool,
    missing_recommendation: &'a str,
}

fn executable_capability(spec: ExecutableSpec<'_>) -> Capability {
    if !spec.path.is_file() {
        let mut item = capability(
            spec.id,
            spec.name,
            spec.category,
            if spec.required_now {
                "unavailable"
            } else {
                "not_installed"
            },
            spec.required_now,
            spec.usage,
            "未在受信任的预期路径检测到组件",
        );
        item.path = Some(spec.path.to_string_lossy().into_owned());
        item.requires_admin = spec.requires_admin;
        item.recommendation = Some(spec.missing_recommendation.into());
        return item;
    }

    let probe = spec.probe_args.map(|args| run_probe(&spec.path, args));
    let (status, detail, recommendation) = match probe {
        Some(Ok(output)) => (
            "available",
            if output.is_empty() {
                "组件存在且功能探测成功".into()
            } else {
                output.lines().next().unwrap_or("功能探测成功").into()
            },
            None,
        ),
        Some(Err(error)) => (
            "degraded",
            format!("组件存在，但功能探测失败：{error}"),
            Some("检查管理员权限、系统策略和组件状态".into()),
        ),
        None => ("available", "已在受信任路径检测到组件".into(), None),
    };
    let mut item = capability(
        spec.id,
        spec.name,
        spec.category,
        status,
        spec.required_now,
        spec.usage,
        detail,
    );
    item.path = Some(spec.path.to_string_lossy().into_owned());
    item.version = fs::metadata(&spec.path)
        .ok()
        .and_then(|metadata| metadata.modified().ok())
        .map(|_| "已检测到可执行文件".into());
    item.requires_admin = spec.requires_admin;
    item.recommendation = recommendation;
    item
}

#[cfg(target_os = "windows")]
fn native_capabilities() -> Vec<Capability> {
    use windows::{
        core::w,
        Win32::{
            NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2},
            System::{
                Performance::{
                    PdhAddEnglishCounterW, PdhCloseQuery, PdhOpenQueryW, PDH_HCOUNTER, PDH_HQUERY,
                },
                SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX},
            },
        },
    };

    let pdh_ok = unsafe {
        let mut query = PDH_HQUERY::default();
        let mut counter = PDH_HCOUNTER::default();
        let opened = PdhOpenQueryW(None, 0, &mut query) == 0;
        let added = opened
            && PdhAddEnglishCounterW(
                query,
                w!(r"\PhysicalDisk(_Total)\Avg. Disk sec/Transfer"),
                0,
                &mut counter,
            ) == 0;
        if opened {
            let _ = PdhCloseQuery(query);
        }
        added
    };
    let memory_ok = unsafe {
        let mut memory = MEMORYSTATUSEX {
            dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
            ..Default::default()
        };
        GlobalMemoryStatusEx(&mut memory).is_ok()
    };
    let network_ok = unsafe {
        let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
        let result = GetIfTable2(&mut table);
        if !table.is_null() {
            FreeMibTable(table.cast());
        }
        result.is_ok()
    };

    [
        ("pdh", "PDH 性能计数器", pdh_ok, "采集磁盘延迟与队列长度"),
        (
            "memory_api",
            "Windows 内存状态 API",
            memory_ok,
            "采集 Commit 与可用内存",
        ),
        (
            "ip_helper",
            "IP Helper 网络统计",
            network_ok,
            "采集网卡错误与丢弃计数",
        ),
    ]
    .into_iter()
    .map(|(id, name, available, usage)| {
        let mut item = capability(
            id,
            name,
            "基础采集",
            if available {
                "available"
            } else {
                "unavailable"
            },
            true,
            usage,
            if available {
                "原生 API 调用成功"
            } else {
                "原生 API 调用失败"
            },
        );
        if !available {
            item.recommendation = Some("检查 Windows 系统组件和安全策略".into());
        }
        item
    })
    .collect()
}

#[cfg(not(target_os = "windows"))]
fn native_capabilities() -> Vec<Capability> {
    Vec::new()
}

fn first_existing(paths: impl IntoIterator<Item = PathBuf>) -> Option<PathBuf> {
    paths.into_iter().find(|path| path.is_file())
}

async fn ollama_capability(settings: &Settings) -> Capability {
    if settings.ai_mode != "ollama" {
        return capability(
            "ollama",
            "Ollama 本地模型",
            "本地分析",
            "disabled",
            false,
            "使用本地模型解释已提取证据",
            "本地 AI 当前已关闭",
        );
    }
    if !crate::ai::is_local_endpoint(&settings.ollama_endpoint) {
        let mut item = capability(
            "ollama",
            "Ollama 本地模型",
            "本地分析",
            "misconfigured",
            false,
            "使用本地模型解释已提取证据",
            "服务地址不是允许的本机端点",
        );
        item.recommendation = Some("将地址设置为 localhost、127.0.0.1 或 ::1".into());
        return item;
    }

    let url = format!(
        "{}/api/tags",
        settings.ollama_endpoint.trim_end_matches('/')
    );
    let response = reqwest::Client::new()
        .get(url)
        .timeout(Duration::from_secs(3))
        .send()
        .await;
    let mut item = match response {
        Ok(response) if response.status().is_success() => {
            let payload = response.json::<serde_json::Value>().await.ok();
            let model_found = payload
                .as_ref()
                .and_then(|value| value.get("models"))
                .and_then(|value| value.as_array())
                .is_some_and(|models| {
                    models.iter().any(|model| {
                        ["name", "model"].iter().any(|key| {
                            model.get(key).and_then(|value| value.as_str())
                                == Some(settings.ollama_model.as_str())
                        })
                    })
                });
            if model_found {
                capability(
                    "ollama",
                    "Ollama 本地模型",
                    "本地分析",
                    "available",
                    false,
                    "使用本地模型解释已提取证据",
                    format!("服务可用，模型 {} 已安装", settings.ollama_model),
                )
            } else {
                let mut value = capability(
                    "ollama",
                    "Ollama 本地模型",
                    "本地分析",
                    "misconfigured",
                    false,
                    "使用本地模型解释已提取证据",
                    format!("服务可用，但未检测到模型 {}", settings.ollama_model),
                );
                value.recommendation = Some(format!("运行 ollama pull {}", settings.ollama_model));
                value
            }
        }
        Ok(response) => {
            let mut value = capability(
                "ollama",
                "Ollama 本地模型",
                "本地分析",
                "degraded",
                false,
                "使用本地模型解释已提取证据",
                format!("本地服务返回 HTTP {}", response.status()),
            );
            value.recommendation = Some("检查 Ollama 服务状态和服务地址".into());
            value
        }
        Err(error) => {
            let mut value = capability(
                "ollama",
                "Ollama 本地模型",
                "本地分析",
                "unavailable",
                false,
                "使用本地模型解释已提取证据",
                format!("无法连接本地服务：{error}"),
            );
            value.recommendation = Some("启动 Ollama，或在设置中关闭本地 AI".into());
            value
        }
    };
    item.path = Some(settings.ollama_endpoint.clone());
    item
}

pub(crate) async fn detect(
    root: &Path,
    settings: &Settings,
    logman_runtime_status: &str,
) -> CapabilityReport {
    let elevated = is_elevated();
    let mut capabilities = native_capabilities();

    let mut privilege = capability(
        "elevation",
        "管理员权限",
        "运行环境",
        if elevated {
            "available"
        } else {
            "permission_required"
        },
        true,
        "管理性能数据收集器和受保护事件日志",
        if elevated {
            "当前进程已提升权限"
        } else {
            "当前进程未提升权限，部分诊断会降级"
        },
    );
    privilege.requires_admin = true;
    if !elevated {
        privilege.recommendation = Some("以管理员身份重新启动应用".into());
    }
    capabilities.insert(0, privilege);

    let mut logman = executable_capability(ExecutableSpec {
        id: "logman",
        name: "logman 性能日志",
        category: "基础采集",
        required_now: true,
        usage: "维护有大小上限的循环 BLG",
        path: system_tool("logman.exe"),
        probe_args: Some(&["query", "-ets"]),
        requires_admin: true,
        missing_recommendation: "修复 Windows 性能日志组件",
    });
    if logman_runtime_status.starts_with("降级") {
        logman.status = "degraded".into();
        logman.detail = logman_runtime_status.into();
        logman.recommendation = Some("检查管理员权限和性能日志服务".into());
    } else if logman_runtime_status.starts_with("运行中") {
        logman.detail = logman_runtime_status.into();
    }
    capabilities.push(logman);
    capabilities.push(executable_capability(ExecutableSpec {
        id: "wevtutil",
        name: "Windows 事件日志",
        category: "基础采集",
        required_now: true,
        usage: "导出事故时间窗口内的 System 与 Application 事件",
        path: system_tool("wevtutil.exe"),
        probe_args: Some(&["gli", "System"]),
        requires_admin: true,
        missing_recommendation: "修复 Windows Event Log 服务或系统组件",
    }));
    capabilities.push(executable_capability(ExecutableSpec {
        id: "wpr",
        name: "Windows Performance Recorder",
        category: "高级诊断",
        required_now: false,
        usage: "后续用于高精度 ETW 环形采集",
        path: system_tool("wpr.exe"),
        probe_args: Some(&["-status"]),
        requires_admin: true,
        missing_recommendation: "安装与当前 Windows 匹配的 Windows Performance Toolkit",
    }));

    let tools = root.join("tools");
    let procdump = first_existing([tools.join("procdump64.exe"), tools.join("procdump.exe")])
        .unwrap_or_else(|| tools.join("procdump64.exe"));
    capabilities.push(executable_capability(ExecutableSpec {
        id: "procdump",
        name: "ProcDump",
        category: "高级诊断",
        required_now: false,
        usage: "后续用于用户授权的进程 Dump",
        path: procdump,
        probe_args: None,
        requires_admin: true,
        missing_recommendation: "从 Microsoft Sysinternals 获取后放入应用 tools 目录",
    }));

    let program_files_x86 = PathBuf::from(
        env::var_os("ProgramFiles(x86)").unwrap_or_else(|| "C:\\Program Files (x86)".into()),
    );
    let wpa = program_files_x86
        .join("Windows Kits")
        .join("10")
        .join("Windows Performance Toolkit")
        .join("wpa.exe");
    capabilities.push(executable_capability(ExecutableSpec {
        id: "wpa",
        name: "Windows Performance Analyzer",
        category: "高级诊断",
        required_now: false,
        usage: "供专家手动检查 ETL 记录",
        path: wpa,
        probe_args: None,
        requires_admin: false,
        missing_recommendation: "通过 Windows ADK 安装 Windows Performance Toolkit",
    }));

    let windbg = first_existing([
        program_files_x86
            .join("Windows Kits")
            .join("10")
            .join("Debuggers")
            .join("x64")
            .join("windbg.exe"),
        PathBuf::from(env::var_os("LOCALAPPDATA").unwrap_or_default())
            .join("Microsoft")
            .join("WindowsApps")
            .join("WinDbgX.exe"),
    ])
    .unwrap_or_else(|| {
        program_files_x86
            .join("Windows Kits")
            .join("10")
            .join("Debuggers")
            .join("x64")
            .join("windbg.exe")
    });
    capabilities.push(executable_capability(ExecutableSpec {
        id: "windbg",
        name: "WinDbg",
        category: "高级诊断",
        required_now: false,
        usage: "后续用于人工或自动化 Dump 分析",
        path: windbg,
        probe_args: None,
        requires_admin: true,
        missing_recommendation: "安装 Microsoft WinDbg 或 Windows SDK Debugging Tools",
    }));
    capabilities.push(ollama_capability(settings).await);

    let available = capabilities
        .iter()
        .filter(|item| item.status == "available")
        .count();
    let attention = capabilities
        .iter()
        .filter(|item| {
            item.required_now
                && !matches!(
                    item.status.as_str(),
                    "available" | "disabled" | "not_installed"
                )
        })
        .count();
    CapabilityReport {
        checked_at: Utc::now().to_rfc3339(),
        is_elevated: elevated,
        available,
        attention,
        capabilities,
    }
}
