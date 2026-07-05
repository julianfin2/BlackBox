use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const PROFILE: &str = include_str!("../resources/SystemBlackBox.wprp");

#[derive(Debug, Serialize, Clone)]
pub(crate) struct WprStatus {
    pub available: bool,
    pub running: bool,
    pub detail: String,
    pub profile_path: String,
}

fn executable() -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()))
        .join("System32")
        .join("wpr.exe")
}

fn profile_path(root: &Path) -> PathBuf {
    root.join("tools").join("SystemBlackBox.wprp")
}

fn ownership_path(root: &Path) -> PathBuf {
    root.join("wpr-session.lock")
}

fn ensure_profile(root: &Path) -> Result<PathBuf, String> {
    let path = profile_path(root);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(&path, PROFILE).map_err(|error| error.to_string())?;
    Ok(path)
}

fn output_detail(output: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    [stdout.trim(), stderr.trim()]
        .into_iter()
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join("；")
}

fn indicates_running(detail: &str) -> bool {
    let lower = detail.to_ascii_lowercase();
    (lower.contains("is recording")
        || lower.contains("recording profile")
        || detail.contains("正在记录"))
        && !lower.contains("not recording")
}

pub(crate) fn status(root: &Path) -> WprStatus {
    let executable = executable();
    let profile = profile_path(root);
    if !executable.is_file() {
        return WprStatus {
            available: false,
            running: false,
            detail: "未安装 Windows Performance Recorder".into(),
            profile_path: profile.to_string_lossy().into_owned(),
        };
    }
    match Command::new(executable).arg("-status").output() {
        Ok(output) => {
            let detail = output_detail(&output);
            let running = output.status.success() && indicates_running(&detail);
            WprStatus {
                available: true,
                running,
                detail: if detail.is_empty() {
                    if running {
                        "WPR 环形会话正在运行"
                    } else {
                        "WPR 当前未运行"
                    }
                    .into()
                } else {
                    detail
                },
                profile_path: profile.to_string_lossy().into_owned(),
            }
        }
        Err(error) => WprStatus {
            available: true,
            running: false,
            detail: error.to_string(),
            profile_path: profile.to_string_lossy().into_owned(),
        },
    }
}

pub(crate) fn start(root: &Path) -> String {
    let executable = executable();
    if !executable.is_file() {
        return "不可用：未安装 WPR".into();
    }
    let profile = match ensure_profile(root) {
        Ok(path) => path,
        Err(error) => return format!("WPR Profile 写入失败：{error}"),
    };
    let current = status(root);
    if current.running {
        return if ownership_path(root).is_file() {
            "运行中（WPR 内存环形会话）".into()
        } else {
            "降级：检测到其他程序正在使用 WPR，未抢占现有会话".into()
        };
    }
    let _ = fs::remove_file(ownership_path(root));
    let profile_argument = format!("{}!SystemBlackBox", profile.to_string_lossy());
    match Command::new(executable)
        .args(["-start", &profile_argument])
        .output()
    {
        Ok(output) if output.status.success() => {
            let _ = fs::write(
                ownership_path(root),
                format!("started_at={}", chrono::Utc::now().to_rfc3339()),
            );
            "运行中（WPR 内存环形会话）".into()
        }
        Ok(output) => format!("降级：WPR 启动失败（{}）", output_detail(&output)),
        Err(error) => format!("降级：WPR 不可用（{error}）"),
    }
}

pub(crate) fn freeze(root: &Path, destination: &Path, restart: bool) -> String {
    let executable = executable();
    if !executable.is_file() {
        return "未生成 ETL：WPR 不可用".into();
    }
    if !ownership_path(root).is_file() {
        return "未生成 ETL：当前没有由系统黑盒子管理的 WPR 会话".into();
    }
    if fs::create_dir_all(destination).is_err() {
        return "未生成 ETL：无法创建证据目录".into();
    }
    let output_path = destination.join("high-precision.etl");
    let (result, stopped) = match Command::new(&executable)
        .arg("-stop")
        .arg(&output_path)
        .output()
    {
        Ok(output) if output.status.success() => (
            format!("WPR 事故窗口已冻结：{}", output_path.to_string_lossy()),
            true,
        ),
        Ok(output) => (
            format!("WPR ETL 冻结失败：{}", output_detail(&output)),
            false,
        ),
        Err(error) => (format!("WPR ETL 冻结失败：{error}"), false),
    };
    if stopped {
        let _ = fs::remove_file(ownership_path(root));
    }
    if restart && stopped {
        let restart_status = start(root);
        format!("{result}；{restart_status}")
    } else {
        result
    }
}

pub(crate) fn stop(root: &Path) {
    let executable = executable();
    if executable.is_file()
        && ownership_path(root).is_file()
        && Command::new(executable)
            .arg("-cancel")
            .output()
            .is_ok_and(|output| output.status.success())
    {
        let _ = fs::remove_file(ownership_path(root));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_profile_is_memory_backed_and_contains_required_providers() {
        assert!(PROFILE.contains("LoggingMode=\"Memory\""));
        for keyword in [
            "ProcessThread",
            "CSwitch",
            "DiskIO",
            "FileIO",
            "DPC",
            "Interrupt",
        ] {
            assert!(PROFILE.contains(keyword), "missing {keyword}");
        }
    }

    #[test]
    fn embedded_profile_is_well_formed_xml() {
        let mut reader = quick_xml::Reader::from_str(PROFILE);
        let mut buffer = Vec::new();
        loop {
            match reader.read_event_into(&mut buffer) {
                Ok(quick_xml::events::Event::Eof) => break,
                Ok(_) => {}
                Err(error) => panic!("invalid WPR profile XML: {error}"),
            }
            buffer.clear();
        }
    }

    #[test]
    fn wpr_status_does_not_treat_not_recording_as_running() {
        assert!(!indicates_running("WPR is not recording"));
        assert!(indicates_running(
            "WPR is recording using the following set of profile(s): SystemBlackBox"
        ));
        assert!(indicates_running("WPR 正在记录以下配置文件"));
    }
}
