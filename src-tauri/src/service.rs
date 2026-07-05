use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use crate::{
    collector, create_incident_internal, load_or_create_machine_id, read_json, write_json,
    IncidentDraft, IncidentRuntime, Settings,
};

const SERVICE_NAME: &str = "SystemBlackBox";
const PIPE_NAME: &str = r"\\.\pipe\SystemBlackBox.v1";
const PIPE_SECURITY_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ServiceConfig {
    data_root: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ServiceStatus {
    pub installed: bool,
    pub running: bool,
    pub connected: bool,
    pub detail: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RuntimeSnapshot {
    pub(crate) monitoring: bool,
    pub(crate) latest: collector::Sample,
    pub(crate) logman_status: String,
    pub(crate) wpr_status: String,
    pub(crate) uptime_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum IpcRequest {
    Ping {
        token: String,
    },
    Runtime {
        token: String,
    },
    SetMonitoring {
        token: String,
        enabled: bool,
    },
    CreateIncident {
        token: String,
        draft: IncidentDraft,
        trigger_time: Option<String>,
        trigger_source: String,
    },
    ReloadSettings {
        token: String,
    },
    Stop {
        token: String,
    },
}

impl IpcRequest {
    fn token(&self) -> &str {
        match self {
            Self::Ping { token }
            | Self::Runtime { token }
            | Self::SetMonitoring { token, .. }
            | Self::CreateIncident { token, .. }
            | Self::ReloadSettings { token }
            | Self::Stop { token } => token,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct IpcResponse {
    ok: bool,
    error: Option<String>,
    runtime: Option<RuntimeSnapshot>,
    incident_id: Option<String>,
}

impl IpcResponse {
    fn ok() -> Self {
        Self {
            ok: true,
            error: None,
            runtime: None,
            incident_id: None,
        }
    }

    fn error(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(error.into()),
            runtime: None,
            incident_id: None,
        }
    }
}

struct ServiceCore {
    root: PathBuf,
    started: Instant,
    monitoring: Arc<AtomicBool>,
    latest: Arc<Mutex<collector::Sample>>,
    logman_status: Arc<Mutex<String>>,
    wpr_status: Arc<Mutex<String>>,
    incident_runtime: IncidentRuntime,
    stop: Arc<AtomicBool>,
    token: String,
}

fn config_path() -> PathBuf {
    PathBuf::from(std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into()))
        .join("SystemBlackBox")
        .join("service.json")
}

fn read_config() -> Result<ServiceConfig, String> {
    read_json(&config_path())
}

fn ensure_token(root: &Path) -> Result<String, String> {
    let path = root.join("ipc-token");
    if let Ok(token) = fs::read_to_string(&path) {
        let token = token.trim();
        if !token.is_empty() {
            return Ok(token.into());
        }
    }
    let token = uuid::Uuid::new_v4().simple().to_string();
    fs::create_dir_all(root).map_err(|error| error.to_string())?;
    fs::write(path, &token).map_err(|error| error.to_string())?;
    Ok(token)
}

fn token_for_root(root: &Path) -> Result<String, String> {
    fs::read_to_string(root.join("ipc-token"))
        .map(|value| value.trim().to_owned())
        .map_err(|error| error.to_string())
}

fn runtime_snapshot(core: &ServiceCore) -> RuntimeSnapshot {
    RuntimeSnapshot {
        monitoring: core.monitoring.load(Ordering::Relaxed),
        latest: core
            .latest
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone(),
        logman_status: core
            .logman_status
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone(),
        wpr_status: core
            .wpr_status
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone(),
        uptime_seconds: core.started.elapsed().as_secs(),
    }
}

fn handle_request(core: &ServiceCore, request: IpcRequest) -> IpcResponse {
    if request.token() != core.token {
        return IpcResponse::error("IPC 身份验证失败");
    }
    match request {
        IpcRequest::Ping { .. } => IpcResponse::ok(),
        IpcRequest::Runtime { .. } => IpcResponse {
            runtime: Some(runtime_snapshot(core)),
            ..IpcResponse::ok()
        },
        IpcRequest::SetMonitoring { enabled, .. } => {
            let _guard = core
                .incident_runtime
                .io_lock
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            core.monitoring.store(enabled, Ordering::Relaxed);
            let settings: Settings =
                read_json(&core.root.join("settings.json")).unwrap_or_default();
            let (logman_status, wpr_status) = if enabled {
                let logman = collector::start_logman(
                    &core.root,
                    settings.sample_interval_seconds,
                    settings.rolling_limit_gb * 768,
                );
                let wpr = crate::wpr::start(&core.root);
                (logman, wpr)
            } else {
                collector::stop_logman();
                crate::wpr::stop(&core.root);
                ("已暂停".into(), "已暂停".into())
            };
            *core
                .logman_status
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = logman_status;
            *core
                .wpr_status
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = wpr_status;
            IpcResponse {
                runtime: Some(runtime_snapshot(core)),
                ..IpcResponse::ok()
            }
        }
        IpcRequest::CreateIncident {
            draft,
            trigger_time,
            trigger_source,
            ..
        } => {
            let latest = core
                .latest
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .clone();
            match create_incident_internal(
                &core.root,
                &latest,
                draft,
                trigger_time,
                &trigger_source,
                core.incident_runtime.clone(),
            ) {
                Ok(incident) => IpcResponse {
                    incident_id: Some(incident.id),
                    ..IpcResponse::ok()
                },
                Err(error) => IpcResponse::error(error),
            }
        }
        IpcRequest::ReloadSettings { .. } => {
            let _guard = core
                .incident_runtime
                .io_lock
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let settings: Settings =
                read_json(&core.root.join("settings.json")).unwrap_or_default();
            if core.monitoring.load(Ordering::Relaxed) {
                let status = collector::start_logman(
                    &core.root,
                    settings.sample_interval_seconds,
                    settings.rolling_limit_gb * 768,
                );
                *core
                    .logman_status
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = status;
            }
            IpcResponse::ok()
        }
        IpcRequest::Stop { .. } => {
            core.stop.store(true, Ordering::Release);
            IpcResponse::ok()
        }
    }
}

#[cfg(windows)]
fn serve_pipe(core: Arc<ServiceCore>) -> Result<(), String> {
    use std::os::windows::io::FromRawHandle;
    use windows::{
        core::PCWSTR,
        Win32::{
            Foundation::{CloseHandle, LocalFree, ERROR_PIPE_CONNECTED, HLOCAL},
            Security::{
                Authorization::{
                    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
                },
                PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
            },
            Storage::FileSystem::PIPE_ACCESS_DUPLEX,
            System::Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_MESSAGE,
                PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
            },
        },
    };

    let name = PIPE_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let security_sddl = PIPE_SECURITY_SDDL
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(security_sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
        .map_err(|error| format!("创建 IPC 安全描述符失败：{error}"))?;
    }
    let security_attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: false.into(),
    };
    while !core.stop.load(Ordering::Acquire) {
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(name.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                65_536,
                65_536,
                1_000,
                Some(&security_attributes),
            )
        };
        if handle.is_invalid() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(descriptor.0)));
            }
            return Err(windows::core::Error::from_win32().to_string());
        }
        let connected = match unsafe { ConnectNamedPipe(handle, None) } {
            Ok(()) => true,
            Err(error)
                if error.code() == windows::core::HRESULT::from_win32(ERROR_PIPE_CONNECTED.0) =>
            {
                true
            }
            Err(_) => false,
        };
        if !connected {
            unsafe {
                let _ = CloseHandle(handle);
            }
            continue;
        }
        let mut file =
            unsafe { fs::File::from_raw_handle(handle.0 as std::os::windows::io::RawHandle) };
        let mut line = String::new();
        {
            let mut reader = BufReader::new(&mut file).take(65_537);
            if reader.read_line(&mut line).is_err() {
                continue;
            }
        }
        let response = if line.len() > 65_536 {
            IpcResponse::error("IPC 请求超过 64 KiB 上限")
        } else {
            serde_json::from_str::<IpcRequest>(&line)
                .map(|request| handle_request(&core, request))
                .unwrap_or_else(|error| IpcResponse::error(format!("IPC 请求无效：{error}")))
        };
        let bytes = serde_json::to_vec(&response).map_err(|error| error.to_string())?;
        file.write_all(&bytes).map_err(|error| error.to_string())?;
        file.write_all(b"\n").map_err(|error| error.to_string())?;
        let _ = file.flush();
    }
    unsafe {
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
    }
    Ok(())
}

#[cfg(not(windows))]
fn serve_pipe(_core: Arc<ServiceCore>) -> Result<(), String> {
    Err("Windows Named Pipe 仅在 Windows 上可用".into())
}

#[cfg(windows)]
fn send(_root: &Path, request: IpcRequest) -> Result<IpcResponse, String> {
    use std::os::windows::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0)
        .open(PIPE_NAME)
        .map_err(|error| error.to_string())?;
    serde_json::to_writer(&mut file, &request).map_err(|error| error.to_string())?;
    file.write_all(b"\n").map_err(|error| error.to_string())?;
    file.flush().map_err(|error| error.to_string())?;
    let mut line = String::new();
    BufReader::new(file)
        .read_line(&mut line)
        .map_err(|error| error.to_string())?;
    let response: IpcResponse = serde_json::from_str(&line).map_err(|error| error.to_string())?;
    if response.ok {
        Ok(response)
    } else {
        Err(response.error.unwrap_or_else(|| "Service IPC 失败".into()))
    }
}

#[cfg(not(windows))]
fn send(_root: &Path, _request: IpcRequest) -> Result<IpcResponse, String> {
    Err("Windows Service 仅在 Windows 上可用".into())
}

pub(crate) fn ping(root: &Path) -> bool {
    let Ok(token) = token_for_root(root) else {
        return false;
    };
    send(root, IpcRequest::Ping { token }).is_ok()
}

pub(crate) fn runtime(root: &Path) -> Result<RuntimeSnapshot, String> {
    let token = token_for_root(root)?;
    send(root, IpcRequest::Runtime { token })?
        .runtime
        .ok_or_else(|| "Service 未返回运行状态".into())
}

pub(crate) fn set_monitoring(root: &Path, enabled: bool) -> Result<RuntimeSnapshot, String> {
    let token = token_for_root(root)?;
    send(root, IpcRequest::SetMonitoring { token, enabled })?
        .runtime
        .ok_or_else(|| "Service 未返回运行状态".into())
}

pub(crate) fn reload_settings(root: &Path) {
    if let Ok(token) = token_for_root(root) {
        let _ = send(root, IpcRequest::ReloadSettings { token });
    }
}

pub(crate) fn create_incident(
    root: &Path,
    draft: IncidentDraft,
    trigger_time: Option<String>,
    trigger_source: &str,
) -> Result<String, String> {
    let token = token_for_root(root)?;
    send(
        root,
        IpcRequest::CreateIncident {
            token,
            draft,
            trigger_time,
            trigger_source: trigger_source.into(),
        },
    )?
    .incident_id
    .ok_or_else(|| "Service 未返回事故 ID".into())
}

fn run_core(stop: Arc<AtomicBool>) -> Result<(), String> {
    let config = read_config()?;
    let root = config.data_root;
    fs::create_dir_all(root.join("incidents")).map_err(|error| error.to_string())?;
    fs::create_dir_all(root.join("rolling")).map_err(|error| error.to_string())?;
    crate::storage::initialize(&root)?;
    if !root.join("settings.json").is_file() {
        write_json(&root.join("settings.json"), &Settings::default())?;
    }
    let _ = load_or_create_machine_id(&root)?;
    let token = ensure_token(&root)?;
    let monitoring = Arc::new(AtomicBool::new(true));
    let latest = Arc::new(Mutex::new(collector::Sample::default()));
    let io_lock = Arc::new(Mutex::new(()));
    let cancellations = Arc::new(Mutex::new(std::collections::HashMap::new()));
    collector::spawn(
        root.clone(),
        monitoring.clone(),
        latest.clone(),
        io_lock.clone(),
    );
    let settings: Settings = read_json(&root.join("settings.json")).unwrap_or_default();
    let logman_status = Arc::new(Mutex::new(collector::start_logman(
        &root,
        settings.sample_interval_seconds,
        settings.rolling_limit_gb * 768,
    )));
    let wpr_status = Arc::new(Mutex::new(crate::wpr::start(&root)));
    let core = Arc::new(ServiceCore {
        root,
        started: Instant::now(),
        monitoring: monitoring.clone(),
        latest,
        logman_status,
        wpr_status,
        incident_runtime: IncidentRuntime {
            io_lock,
            monitoring,
            cancellations,
        },
        stop: stop.clone(),
        token,
    });
    crate::auto_trigger::spawn(
        core.root.clone(),
        core.latest.clone(),
        core.incident_runtime.clone(),
        core.monitoring.clone(),
    );
    let pipe_core = core.clone();
    std::thread::Builder::new()
        .name("blackbox-service-ipc".into())
        .spawn(move || {
            let _ = serve_pipe(pipe_core);
        })
        .map_err(|error| error.to_string())?;
    while !stop.load(Ordering::Acquire) {
        std::thread::sleep(Duration::from_millis(250));
    }
    core.monitoring.store(false, Ordering::Release);
    collector::stop_logman();
    crate::wpr::stop(&core.root);
    Ok(())
}

#[cfg(windows)]
pub fn run_dispatcher() -> Result<(), String> {
    use std::ffi::OsString;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(_arguments: Vec<OsString>) {
        let stop = Arc::new(AtomicBool::new(false));
        let handler_stop = stop.clone();
        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Stop => {
                    handler_stop.store(true, Ordering::Release);
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };
        let Ok(status_handle) = service_control_handler::register(SERVICE_NAME, event_handler)
        else {
            return;
        };
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        });
        let result = run_core(stop);
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: if result.is_ok() {
                ServiceExitCode::Win32(0)
            } else {
                ServiceExitCode::ServiceSpecific(1)
            },
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        });
    }

    service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(|error| error.to_string())
}

#[cfg(not(windows))]
pub fn run_dispatcher() -> Result<(), String> {
    Err("Windows Service 仅支持 Windows".into())
}

pub(crate) fn install(data_root: &Path) -> Result<ServiceStatus, String> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    write_json(
        &path,
        &ServiceConfig {
            data_root: data_root.to_path_buf(),
        },
    )?;
    let _ = ensure_token(data_root)?;
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let binary_path = format!("\"{}\" --service", executable.to_string_lossy());
    let create = std::process::Command::new("sc.exe")
        .args([
            "create",
            SERVICE_NAME,
            "start=",
            "auto",
            "DisplayName=",
            "系统黑盒子采集服务",
            "binPath=",
            &binary_path,
        ])
        .output()
        .map_err(|error| error.to_string())?;
    if !create.status.success()
        && !String::from_utf8_lossy(&create.stdout).contains("1073")
        && !String::from_utf8_lossy(&create.stderr).contains("1073")
    {
        return Err(format!(
            "安装 Service 失败：{}{}",
            String::from_utf8_lossy(&create.stdout),
            String::from_utf8_lossy(&create.stderr)
        ));
    }
    let _ = std::process::Command::new("sc.exe")
        .args([
            "description",
            SERVICE_NAME,
            "持续记录系统状态并冻结事故证据",
        ])
        .output();
    let start = std::process::Command::new("sc.exe")
        .args(["start", SERVICE_NAME])
        .output()
        .map_err(|error| error.to_string())?;
    if !start.status.success()
        && !String::from_utf8_lossy(&start.stdout).contains("1056")
        && !String::from_utf8_lossy(&start.stderr).contains("1056")
    {
        return Err(format!(
            "Service 已安装但启动失败：{}{}",
            String::from_utf8_lossy(&start.stdout),
            String::from_utf8_lossy(&start.stderr)
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let status = query(data_root);
        if status.connected || !status.running || Instant::now() >= deadline {
            return Ok(status);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

pub(crate) fn uninstall(data_root: &Path) -> Result<ServiceStatus, String> {
    let _ = std::process::Command::new("sc.exe")
        .args(["stop", SERVICE_NAME])
        .output();
    let deadline = Instant::now() + Duration::from_secs(8);
    while query(data_root).running && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
    }
    let output = std::process::Command::new("sc.exe")
        .args(["delete", SERVICE_NAME])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "卸载 Service 失败：{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(query(data_root))
}

pub(crate) fn query(data_root: &Path) -> ServiceStatus {
    let output = std::process::Command::new("sc.exe")
        .args(["query", SERVICE_NAME])
        .output();
    let detail = output
        .as_ref()
        .map(|value| {
            format!(
                "{}{}",
                String::from_utf8_lossy(&value.stdout),
                String::from_utf8_lossy(&value.stderr)
            )
        })
        .unwrap_or_else(|error| error.to_string());
    let installed = output.is_ok_and(|value| value.status.success());
    let running = detail.contains("RUNNING") || detail.contains("正在运行");
    ServiceStatus {
        installed,
        running,
        connected: ping(data_root),
        detail: detail.trim().into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_protocol_rejects_arbitrary_commands() {
        assert!(serde_json::from_str::<IpcRequest>(
            r#"{"command":"run_shell","token":"x","script":"format c:"}"#
        )
        .is_err());
    }

    #[test]
    fn ipc_protocol_is_versioned_named_pipe() {
        assert!(PIPE_NAME.ends_with(".v1"));
        assert!(!PIPE_NAME.starts_with("http"));
    }

    #[test]
    fn pipe_acl_and_token_authentication_restrict_requests() {
        assert!(PIPE_SECURITY_SDDL.contains(";;;SY"));
        assert!(PIPE_SECURITY_SDDL.contains(";;;BA"));
        assert!(PIPE_SECURITY_SDDL.contains(";;;AU"));
        let monitoring = Arc::new(AtomicBool::new(true));
        let core = ServiceCore {
            root: PathBuf::from("test"),
            started: Instant::now(),
            monitoring: monitoring.clone(),
            latest: Arc::new(Mutex::new(collector::Sample::default())),
            logman_status: Arc::new(Mutex::new(String::new())),
            wpr_status: Arc::new(Mutex::new(String::new())),
            incident_runtime: IncidentRuntime {
                io_lock: Arc::new(Mutex::new(())),
                monitoring,
                cancellations: Arc::new(Mutex::new(std::collections::HashMap::new())),
            },
            stop: Arc::new(AtomicBool::new(false)),
            token: "expected-token".into(),
        };

        let response = handle_request(
            &core,
            IpcRequest::SetMonitoring {
                token: "wrong-token".into(),
                enabled: false,
            },
        );

        assert!(!response.ok);
        assert!(core.monitoring.load(Ordering::Relaxed));
    }
}
