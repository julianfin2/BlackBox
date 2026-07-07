use crate::analysis::{parse_windows_events, WindowsEventRecord};

#[derive(Clone)]
pub(crate) struct DetectedRecovery {
    pub event_time: Option<String>,
    pub evidence_summary: String,
}

#[cfg(target_os = "windows")]
pub(crate) fn detect_unexpected_restart() -> Option<DetectedRecovery> {
    use std::process::Command;

    let query =
        "*[System[(EventID=12 or EventID=41 or EventID=1001 or EventID=1074 or EventID=6005 or EventID=6006 or EventID=6008)]]";
    let query_arg = format!("/q:{query}");
    let output = Command::new("wevtutil")
        .args([
            "qe",
            "System",
            &query_arg,
            "/rd:true",
            "/f:RenderedXml",
            "/c:80",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let xml = String::from_utf8_lossy(&output.stdout);
    let events = parse_windows_events(&xml, "System");
    detect_from_events(&events)
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn detect_unexpected_restart() -> Option<DetectedRecovery> {
    None
}

fn detect_from_events(events: &[WindowsEventRecord]) -> Option<DetectedRecovery> {
    let latest_boot_ms = events
        .iter()
        .filter(|event| is_boot_event(event))
        .filter_map(event_time_ms)
        .max();

    if let Some(boot_ms) = latest_boot_ms {
        let boot_window_start = boot_ms.saturating_sub(10 * 60 * 1000);
        let mut candidates: Vec<&WindowsEventRecord> = events
            .iter()
            .filter(|event| is_unexpected_shutdown_event(event) || is_bugcheck_event(event))
            .filter(|event| {
                event_time_ms(event)
                    .map(|time_ms| time_ms >= boot_window_start)
                    .unwrap_or(false)
            })
            .collect();
        candidates.sort_by_key(|event| (event_priority(event), event_time_ms(event).unwrap_or(0)));
        return candidates.last().map(|event| to_detected_recovery(event));
    }

    let latest_normal_shutdown_ms = events
        .iter()
        .filter(|event| is_normal_shutdown_event(event))
        .filter_map(event_time_ms)
        .max();
    events
        .iter()
        .filter(|event| is_unexpected_shutdown_event(event) || is_bugcheck_event(event))
        .filter(|event| {
            let Some(time_ms) = event_time_ms(event) else {
                return false;
            };
            latest_normal_shutdown_ms
                .map(|normal_ms| time_ms > normal_ms)
                .unwrap_or(true)
        })
        .max_by_key(|event| (event_priority(event), event_time_ms(event).unwrap_or(0)))
        .map(to_detected_recovery)
}

fn to_detected_recovery(event: &WindowsEventRecord) -> DetectedRecovery {
    DetectedRecovery {
        event_time: event.timestamp.clone(),
        evidence_summary: event_summary(event),
    }
}

fn event_time_ms(event: &WindowsEventRecord) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(event.timestamp.as_deref()?)
        .ok()
        .map(|value| value.timestamp_millis())
}

fn is_boot_event(event: &WindowsEventRecord) -> bool {
    let provider = event.provider.to_ascii_lowercase();
    event.event_id == Some(6005)
        || (provider.contains("kernel-general") && event.event_id == Some(12))
}

fn is_normal_shutdown_event(event: &WindowsEventRecord) -> bool {
    matches!(event.event_id, Some(1074 | 6006))
}

fn is_unexpected_shutdown_event(event: &WindowsEventRecord) -> bool {
    let provider = event.provider.to_ascii_lowercase();
    (provider.contains("kernel-power") && event.event_id == Some(41))
        || event.event_id == Some(6008)
}

fn is_bugcheck_event(event: &WindowsEventRecord) -> bool {
    let provider = event.provider.to_ascii_lowercase();
    event.event_id == Some(1001)
        && (provider.contains("bugcheck") || provider.contains("wer-systemerrorreporting"))
}

fn event_priority(event: &WindowsEventRecord) -> u8 {
    if is_bugcheck_event(event) {
        3
    } else if event.provider.to_ascii_lowercase().contains("kernel-power")
        && event.event_id == Some(41)
    {
        2
    } else {
        1
    }
}

fn event_summary(event: &WindowsEventRecord) -> String {
    let provider = if event.provider.is_empty() {
        "System"
    } else {
        &event.provider
    };
    match event.event_id {
        Some(1001) if is_bugcheck_event(event) => {
            format!("{provider} 1001：检测到 BugCheck 蓝屏记录")
        }
        Some(41) => format!("{provider} 41：Windows 记录上次系统未正常关闭"),
        Some(6008) => "EventLog 6008：上一次关机是非预期的".into(),
        Some(id) => format!("{provider} {id}：Windows 记录了异常重启相关事件"),
        None => format!("{provider}：Windows 记录了异常重启相关事件"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(provider: &str, id: u32, timestamp: &str) -> WindowsEventRecord {
        WindowsEventRecord {
            provider: provider.into(),
            event_id: Some(id),
            timestamp: Some(timestamp.into()),
            ..Default::default()
        }
    }

    #[test]
    fn normal_shutdown_before_latest_boot_does_not_trigger_recovery() {
        let events = vec![
            event("EventLog", 6005, "2026-07-06T08:00:00Z"),
            event("EventLog", 6006, "2026-07-06T07:59:20Z"),
            event("User32", 1074, "2026-07-06T07:59:00Z"),
        ];

        assert!(detect_from_events(&events).is_none());
    }

    #[test]
    fn kernel_power_near_latest_boot_triggers_recovery() {
        let events = vec![
            event("EventLog", 6005, "2026-07-06T08:00:00Z"),
            event("Microsoft-Windows-Kernel-Power", 41, "2026-07-06T08:00:03Z"),
        ];

        let recovery = detect_from_events(&events).expect("expected recovery candidate");
        assert!(recovery.evidence_summary.contains("Kernel-Power"));
    }

    #[test]
    fn old_kernel_power_before_a_later_normal_boot_is_ignored() {
        let events = vec![
            event("EventLog", 6005, "2026-07-06T09:00:00Z"),
            event("EventLog", 6006, "2026-07-06T08:59:20Z"),
            event("EventLog", 6005, "2026-07-06T08:00:00Z"),
            event("Microsoft-Windows-Kernel-Power", 41, "2026-07-06T08:00:03Z"),
        ];

        assert!(detect_from_events(&events).is_none());
    }
}
