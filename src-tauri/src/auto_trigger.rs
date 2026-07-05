use chrono::Utc;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use crate::{
    collector::Sample, create_incident_internal, read_json, storage, Incident, IncidentDraft,
    IncidentRuntime, Settings,
};

#[derive(Default)]
struct RuleState {
    active_since_ms: HashMap<&'static str, i64>,
    last_trigger_ms: HashMap<String, i64>,
    hourly_triggers_ms: Vec<i64>,
    last_sample_ms: i64,
    last_gpu_check: Option<Instant>,
}

struct Rule {
    id: &'static str,
    symptom: &'static str,
    label: &'static str,
    severity: &'static str,
    active: bool,
    required_ms: i64,
}

fn rules(sample: &Sample) -> Vec<Rule> {
    vec![
        Rule {
            id: "cpu_saturation",
            symptom: "system_slow",
            label: "CPU 持续饱和",
            severity: "high",
            active: sample.cpu_percent >= 95.0,
            required_ms: 10_000,
        },
        Rule {
            id: "commit_pressure",
            symptom: "system_freeze",
            label: "内存 Commit 接近极限",
            severity: "critical",
            active: sample.commit_percent >= 95.0,
            required_ms: 10_000,
        },
        Rule {
            id: "disk_latency",
            symptom: "system_freeze",
            label: "磁盘延迟与队列严重异常",
            severity: "high",
            active: sample.disk_latency_ms >= 500.0 && sample.disk_queue_length >= 4.0,
            required_ms: 6_000,
        },
        Rule {
            id: "dpc_isr",
            symptom: "system_freeze",
            label: "DPC / ISR 占用异常",
            severity: "high",
            active: sample.dpc_percent + sample.interrupt_percent >= 25.0,
            required_ms: 6_000,
        },
        Rule {
            id: "network_loss",
            symptom: "network_slow",
            label: "网络接口持续错误或丢包",
            severity: "medium",
            active: sample.network_errors + sample.network_discards >= 10,
            required_ms: 6_000,
        },
    ]
}

fn sustained(state: &mut RuleState, rule: &Rule, sample_timestamp_ms: i64) -> bool {
    if !rule.active {
        state.active_since_ms.remove(rule.id);
        return false;
    }
    let since = *state
        .active_since_ms
        .entry(rule.id)
        .or_insert(sample_timestamp_ms);
    sample_timestamp_ms - since >= rule.required_ms
}

fn has_active_incident(root: &Path, symptom: &str) -> bool {
    fs::read_dir(root.join("incidents"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| read_json::<Incident>(&entry.path().join("incident.json")).ok())
        .any(|incident| {
            incident.symptom == symptom
                && matches!(
                    incident.status.as_str(),
                    "capturing" | "freezing" | "extracting" | "analyzing"
                )
        })
}

fn allowed(state: &mut RuleState, settings: &Settings, symptom: &str, now_ms: i64) -> bool {
    let hour_ago = now_ms - 3_600_000;
    state
        .hourly_triggers_ms
        .retain(|timestamp| *timestamp >= hour_ago);
    if state.hourly_triggers_ms.len() >= settings.auto_trigger_max_per_hour {
        return false;
    }
    let cooldown_ms = settings.auto_trigger_cooldown_minutes as i64 * 60_000;
    state
        .last_trigger_ms
        .get(symptom)
        .is_none_or(|timestamp| now_ms - *timestamp >= cooldown_ms)
}

fn record_trigger(state: &mut RuleState, symptom: &str, now_ms: i64) {
    state.last_trigger_ms.insert(symptom.into(), now_ms);
    state.hourly_triggers_ms.push(now_ms);
    state.active_since_ms.clear();
}

#[cfg(windows)]
fn recent_gpu_reset() -> bool {
    Command::new("wevtutil")
        .args([
            "qe",
            "System",
            "/q:*[System[Provider[@Name='Display'] and EventID=4101 and TimeCreated[timediff(@SystemTime) <= 15000]]]",
            "/rd:true",
            "/f:text",
            "/c:1",
        ])
        .output()
        .is_ok_and(|output| output.status.success() && !output.stdout.is_empty())
}

#[cfg(not(windows))]
fn recent_gpu_reset() -> bool {
    false
}

fn create_automatic(
    root: &Path,
    latest: &Sample,
    runtime: IncidentRuntime,
    symptom: &str,
    severity: &str,
    reason: &str,
) -> Result<String, String> {
    let incident = create_incident_internal(
        root,
        latest,
        IncidentDraft {
            symptom: symptom.into(),
            severity: severity.into(),
            duration_seconds: 0,
            still_happening: true,
            description: format!("自动触发：{reason}"),
        },
        Some(Utc::now().to_rfc3339()),
        "automatic",
        runtime,
    )?;
    storage::audit(
        root,
        "incident.automatic_triggered",
        Some(&incident.id),
        Some(reason),
    )?;
    Ok(incident.id)
}

pub(crate) fn spawn(
    root: PathBuf,
    latest: Arc<Mutex<Sample>>,
    runtime: IncidentRuntime,
    monitoring: Arc<AtomicBool>,
) {
    thread::Builder::new()
        .name("blackbox-automatic-trigger".into())
        .spawn(move || {
            let mut state = RuleState::default();
            loop {
                thread::sleep(Duration::from_secs(1));
                if !monitoring.load(Ordering::Relaxed) {
                    continue;
                }
                let settings: Settings = read_json(&root.join("settings.json")).unwrap_or_default();
                if !settings.auto_trigger_enabled {
                    state.active_since_ms.clear();
                    continue;
                }
                let sample = latest
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .clone();
                if sample.timestamp_ms <= state.last_sample_ms {
                    continue;
                }
                state.last_sample_ms = sample.timestamp_ms;
                let now_ms = Utc::now().timestamp_millis();
                for rule in rules(&sample) {
                    if !sustained(&mut state, &rule, sample.timestamp_ms)
                        || has_active_incident(&root, rule.symptom)
                        || !allowed(&mut state, &settings, rule.symptom, now_ms)
                    {
                        continue;
                    }
                    if create_automatic(
                        &root,
                        &sample,
                        runtime.clone(),
                        rule.symptom,
                        rule.severity,
                        rule.label,
                    )
                    .is_ok()
                    {
                        record_trigger(&mut state, rule.symptom, now_ms);
                    }
                    break;
                }
                let should_check_gpu = state
                    .last_gpu_check
                    .is_none_or(|last| last.elapsed() >= Duration::from_secs(10));
                if should_check_gpu {
                    state.last_gpu_check = Some(Instant::now());
                    if recent_gpu_reset()
                        && !has_active_incident(&root, "display_issue")
                        && allowed(&mut state, &settings, "display_issue", now_ms)
                        && create_automatic(
                            &root,
                            &sample,
                            runtime.clone(),
                            "display_issue",
                            "high",
                            "检测到 GPU reset（Display Event 4101）",
                        )
                        .is_ok()
                    {
                        record_trigger(&mut state, "display_issue", now_ms);
                    }
                }
            }
        })
        .expect("failed to start automatic trigger");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_require_sustained_thresholds() {
        let sample = Sample {
            cpu_percent: 96.0,
            commit_percent: 96.0,
            disk_latency_ms: 600.0,
            disk_queue_length: 5.0,
            dpc_percent: 20.0,
            interrupt_percent: 10.0,
            network_errors: 10,
            ..Default::default()
        };
        let rules = rules(&sample);
        assert_eq!(rules.iter().filter(|rule| rule.active).count(), 5);
        assert!(rules.iter().all(|rule| rule.required_ms >= 6_000));
    }

    #[test]
    fn sustained_rule_waits_for_duration_and_resets_after_recovery() {
        let mut state = RuleState::default();
        let active = Rule {
            id: "test",
            symptom: "system_slow",
            label: "test",
            severity: "high",
            active: true,
            required_ms: 6_000,
        };
        assert!(!sustained(&mut state, &active, 10_000));
        assert!(!sustained(&mut state, &active, 15_999));
        assert!(sustained(&mut state, &active, 16_000));

        let inactive = Rule {
            active: false,
            ..active
        };
        assert!(!sustained(&mut state, &inactive, 17_000));
        let active_again = Rule {
            active: true,
            ..inactive
        };
        assert!(!sustained(&mut state, &active_again, 20_000));
    }

    #[test]
    fn cooldown_and_hourly_limit_prevent_trigger_storms() {
        let settings = Settings {
            auto_trigger_cooldown_minutes: 15,
            auto_trigger_max_per_hour: 2,
            ..Default::default()
        };
        let mut state = RuleState::default();
        let now = 1_000_000;
        assert!(allowed(&mut state, &settings, "system_slow", now));
        record_trigger(&mut state, "system_slow", now);
        assert!(!allowed(&mut state, &settings, "system_slow", now + 60_000));
        record_trigger(&mut state, "network_slow", now + 1);
        assert!(!allowed(&mut state, &settings, "other", now + 120_000));
    }
}
