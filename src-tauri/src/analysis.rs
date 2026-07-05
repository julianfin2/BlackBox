use crate::{collector::Sample, Cause, Observation, Report, Test};
use quick_xml::{escape::unescape, events::Event, Reader};
use serde::Serialize;

struct ObservationDraft {
    id: String,
    title: String,
    description: String,
    category: String,
    offset_ms: i64,
    severity: String,
    value: Option<f64>,
    unit: Option<String>,
    source: String,
}

fn observation(draft: ObservationDraft) -> Observation {
    Observation {
        id: draft.id,
        title: draft.title,
        description: draft.description,
        source: draft.source,
        category: draft.category,
        offset_ms: draft.offset_ms,
        severity: draft.severity,
        value: draft.value,
        unit: draft.unit,
    }
}

pub(crate) fn extract(
    samples: &[Sample],
    trigger_ms: i64,
    system_events: &str,
    application_events: &str,
) -> Vec<Observation> {
    let mut observations = Vec::new();
    let mut id = 1;
    let mut push = |title: String,
                    description: String,
                    category: &str,
                    sample: &Sample,
                    severity: &str,
                    value: Option<f64>,
                    unit: Option<&str>| {
        observations.push(observation(ObservationDraft {
            id: format!("obs_{id:03}"),
            title,
            description,
            category: category.into(),
            offset_ms: sample.timestamp_ms - trigger_ms,
            severity: severity.into(),
            value,
            unit: unit.map(str::to_owned),
            source: "rolling performance".into(),
        }));
        id += 1;
    };

    if let Some(sample) = sustained(samples, |sample| sample.cpu_percent >= 90.0, 2) {
        push(
            "CPU 持续饱和".into(),
            format!(
                "CPU 使用率连续多个采样点超过 90%，峰值 {:.1}%。",
                sample.cpu_percent
            ),
            "CPU",
            sample,
            "critical",
            Some(sample.cpu_percent as f64),
            Some("%"),
        );
    }
    if let Some(sample) = samples.iter().max_by(|a, b| {
        a.memory_percent
            .partial_cmp(&b.memory_percent)
            .unwrap_or(std::cmp::Ordering::Equal)
    }) {
        if sample.memory_percent >= 90.0 {
            push(
                "可用内存过低".into(),
                format!(
                    "物理内存使用率达到 {:.1}%，剩余 {:.0} MB。",
                    sample.memory_percent,
                    sample.available_memory_bytes as f64 / 1_048_576.0
                ),
                "Memory",
                sample,
                "critical",
                Some(sample.memory_percent),
                Some("%"),
            );
        } else if sample.available_memory_bytes > 0 && sample.available_memory_bytes < 1_073_741_824
        {
            push(
                "可用内存偏低".into(),
                format!(
                    "可用物理内存最低约 {:.0} MB。",
                    sample.available_memory_bytes as f64 / 1_048_576.0
                ),
                "Memory",
                sample,
                "warning",
                Some(sample.available_memory_bytes as f64),
                Some("bytes"),
            );
        }
    }
    if let Some(sample) = sustained(samples, |sample| sample.commit_percent >= 90.0, 2) {
        push(
            "内存 Commit 压力".into(),
            format!(
                "已提交内存连续多个采样点达到 Commit Limit 的 {:.1}%。",
                sample.commit_percent
            ),
            "Memory",
            sample,
            "critical",
            Some(sample.commit_percent),
            Some("%"),
        );
    }
    if let Some(sample) = sustained(samples, |sample| sample.disk_latency_ms >= 500.0, 2) {
        push(
            "磁盘延迟严重升高".into(),
            format!(
                "平均磁盘传输延迟连续多个采样点超过 500 ms，记录值 {:.1} ms。",
                sample.disk_latency_ms
            ),
            "Disk",
            sample,
            "critical",
            Some(sample.disk_latency_ms),
            Some("ms"),
        );
    }
    if let Some(sample) = sustained(samples, |sample| sample.disk_queue_length >= 4.0, 2) {
        push(
            "磁盘队列持续积压".into(),
            format!(
                "磁盘队列长度连续多个采样点不低于 4，记录值 {:.1}。",
                sample.disk_queue_length
            ),
            "Disk",
            sample,
            "warning",
            Some(sample.disk_queue_length),
            Some("requests"),
        );
    }
    if let Some(sample) = samples
        .iter()
        .max_by_key(|sample| sample.disk_read_bytes_per_sec + sample.disk_write_bytes_per_sec)
    {
        let throughput = sample.disk_read_bytes_per_sec + sample.disk_write_bytes_per_sec;
        if throughput > 100 * 1_048_576 {
            push(
                "磁盘吞吐突增".into(),
                format!(
                    "进程磁盘吞吐达到 {:.1} MB/s；该事实不等同于磁盘延迟异常。",
                    throughput as f64 / 1_048_576.0
                ),
                "Disk",
                sample,
                "warning",
                Some(throughput as f64),
                Some("bytes/s"),
            );
        }
    }
    if let Some((sample, process)) = samples
        .iter()
        .flat_map(|sample| {
            sample
                .top_processes
                .iter()
                .map(move |process| (sample, process))
        })
        .max_by(|(_, left), (_, right)| left.cpu_percent.total_cmp(&right.cpu_percent))
    {
        if process.cpu_percent >= 80.0 {
            push(
                "单进程 CPU 峰值".into(),
                format!(
                    "{} 的 CPU 使用率达到 {:.1}%。",
                    process.name, process.cpu_percent
                ),
                "Process",
                sample,
                "warning",
                Some(process.cpu_percent as f64),
                Some("%"),
            );
        }
    }
    if let Some(sample) = samples
        .iter()
        .find(|sample| sample.network_errors > 0 || sample.network_discards > 0)
    {
        push(
            "网络接口错误或丢弃".into(),
            format!(
                "采样间隔内网卡累计新增 {} 个错误和 {} 个丢弃。",
                sample.network_errors, sample.network_discards
            ),
            "Network",
            sample,
            "warning",
            Some((sample.network_errors + sample.network_discards) as f64),
            Some("packets"),
        );
    }
    for fact in parse_windows_events(system_events, "System")
        .into_iter()
        .chain(parse_windows_events(application_events, "Application"))
    {
        let Some((title, description, severity)) = classify_windows_event(&fact) else {
            continue;
        };
        let offset_ms = fact
            .timestamp
            .as_deref()
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.timestamp_millis() - trigger_ms)
            .unwrap_or(0);
        observations.push(observation(ObservationDraft {
            id: format!("obs_{id:03}"),
            title: title.into(),
            description,
            category: "Events".into(),
            offset_ms,
            severity: severity.into(),
            value: fact.event_id.map(|value| value as f64),
            unit: Some("event_id".into()),
            source: format!(
                "Windows Event Log · {} · Event {}",
                fact.provider,
                fact.event_id
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".into())
            ),
        }));
        id += 1;
    }

    if observations.is_empty() {
        observations.push(observation(ObservationDraft {
            id: "obs_001".into(),
            title: "未发现达到阈值的异常".into(),
            description: format!(
                "已检查 {} 个性能采样点和事故窗口内的关键 Windows 事件，当前证据不足以判断根因。",
                samples.len()
            ),
            category: "Events".into(),
            offset_ms: 0,
            severity: "info".into(),
            value: None,
            unit: None,
            source: "deterministic rules".into(),
        }));
    }
    observations
}

#[derive(Default, Serialize, Clone)]
pub(crate) struct WindowsEventRecord {
    pub provider: String,
    pub event_id: Option<u32>,
    pub timestamp: Option<String>,
    pub level: Option<u8>,
    pub channel: String,
    pub computer: String,
    pub message: String,
    pub data: Vec<String>,
}

pub(crate) fn parse_windows_events(xml: &str, fallback_channel: &str) -> Vec<WindowsEventRecord> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut records = Vec::new();
    let mut current = WindowsEventRecord::default();
    let mut inside_event = false;
    let mut text_field: Option<String> = None;
    let mut data_name: Option<String> = None;
    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => match element.local_name().as_ref() {
                b"Event" => {
                    current = WindowsEventRecord {
                        channel: fallback_channel.into(),
                        ..Default::default()
                    };
                    inside_event = true;
                }
                b"EventID" | b"Level" | b"Channel" | b"Computer" | b"Message" if inside_event => {
                    text_field =
                        Some(String::from_utf8_lossy(element.local_name().as_ref()).into_owned());
                }
                b"Data" if inside_event => {
                    text_field = Some("Data".into());
                    data_name = element
                        .attributes()
                        .flatten()
                        .find(|attribute| attribute.key.local_name().as_ref() == b"Name")
                        .and_then(|attribute| {
                            attribute
                                .decode_and_unescape_value(reader.decoder())
                                .ok()
                                .map(|value| value.into_owned())
                        });
                }
                b"Provider" if inside_event => {
                    for attribute in element.attributes().flatten() {
                        if attribute.key.local_name().as_ref() == b"Name" {
                            current.provider = attribute
                                .decode_and_unescape_value(reader.decoder())
                                .map(|value| value.into_owned())
                                .unwrap_or_default();
                        }
                    }
                }
                b"TimeCreated" if inside_event => {
                    for attribute in element.attributes().flatten() {
                        if attribute.key.local_name().as_ref() == b"SystemTime" {
                            current.timestamp = attribute
                                .decode_and_unescape_value(reader.decoder())
                                .map(|value| value.into_owned())
                                .ok();
                        }
                    }
                }
                _ => {}
            },
            Ok(Event::Empty(element)) if inside_event => match element.local_name().as_ref() {
                b"Provider" => {
                    for attribute in element.attributes().flatten() {
                        if attribute.key.local_name().as_ref() == b"Name" {
                            current.provider = attribute
                                .decode_and_unescape_value(reader.decoder())
                                .map(|value| value.into_owned())
                                .unwrap_or_default();
                        }
                    }
                }
                b"TimeCreated" => {
                    for attribute in element.attributes().flatten() {
                        if attribute.key.local_name().as_ref() == b"SystemTime" {
                            current.timestamp = attribute
                                .decode_and_unescape_value(reader.decoder())
                                .map(|value| value.into_owned())
                                .ok();
                        }
                    }
                }
                _ => {}
            },
            Ok(Event::Text(text)) if inside_event => {
                let decoded = text
                    .decode()
                    .map(|value| value.into_owned())
                    .unwrap_or_default();
                let value = unescape(&decoded)
                    .map(|value| value.into_owned())
                    .unwrap_or(decoded);
                match text_field.as_deref() {
                    Some("EventID") => current.event_id = value.parse().ok(),
                    Some("Level") => current.level = value.parse().ok(),
                    Some("Channel") => current.channel = value,
                    Some("Computer") => current.computer = value,
                    Some("Message") => {
                        if !current.message.is_empty() {
                            current.message.push(' ');
                        }
                        current.message.push_str(&value);
                    }
                    Some("Data") if !value.is_empty() => current.data.push(match &data_name {
                        Some(name) if !name.is_empty() => format!("{name}: {value}"),
                        _ => value,
                    }),
                    _ => {}
                }
            }
            Ok(Event::GeneralRef(reference)) if inside_event => {
                let name = reference
                    .decode()
                    .map(|value| value.into_owned())
                    .unwrap_or_default();
                let encoded = format!("&{name};");
                let value = unescape(&encoded)
                    .map(|value| value.into_owned())
                    .unwrap_or(encoded);
                match text_field.as_deref() {
                    Some("Message") => {
                        if !current.message.is_empty() {
                            current.message.push(' ');
                        }
                        current.message.push_str(&value);
                    }
                    Some("Data") if !value.is_empty() => current.data.push(match &data_name {
                        Some(name) if !name.is_empty() => format!("{name}: {value}"),
                        _ => value,
                    }),
                    _ => {}
                }
            }
            Ok(Event::End(element)) => match element.local_name().as_ref() {
                b"EventID" | b"Level" | b"Channel" | b"Computer" | b"Message" | b"Data" => {
                    text_field = None;
                    data_name = None;
                }
                b"Event" => {
                    if inside_event {
                        records.push(current);
                        current = WindowsEventRecord::default();
                        inside_event = false;
                    }
                }
                _ => {}
            },
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    records
}

fn classify_windows_event(
    fact: &WindowsEventRecord,
) -> Option<(&'static str, String, &'static str)> {
    let provider = fact.provider.to_ascii_lowercase();
    let event_id = fact.event_id;
    let (title, description, severity) =
        if provider.contains("kernel-power") && event_id == Some(41) {
            (
                "Kernel-Power 关键事件",
                "Windows 记录了异常关机或电源中断。",
                "critical",
            )
        } else if provider.contains("whea-logger") {
            (
                "WHEA 硬件错误事件",
                "Windows 硬件错误架构在事故窗口内记录了异常。",
                "critical",
            )
        } else if provider.contains("bugcheck")
            || (provider.contains("wer-systemerrorreporting") && event_id == Some(1001))
        {
            (
                "BugCheck 事件",
                "Windows 在事故窗口内记录了错误检查。",
                "critical",
            )
        } else if provider.contains("stornvme")
            || provider.contains("storport")
            || provider == "disk"
            || provider.contains("ntfs")
        {
            (
                "存储驱动事件",
                "存储栈在事故窗口内记录了错误或重置事件。",
                "warning",
            )
        } else if provider.contains("application hang") && event_id == Some(1002) {
            (
                "应用程序挂起事件",
                "Windows 在事故窗口内记录了应用程序无响应。",
                "warning",
            )
        } else if provider.contains("application error") && event_id == Some(1000) {
            (
                "应用程序错误事件",
                "Windows 在事故窗口内记录了应用程序崩溃。",
                "warning",
            )
        } else if provider == "display"
            || provider.contains("nvlddmkm")
            || provider.contains("amdwddmg")
        {
            (
                "显示驱动事件",
                "显示驱动在事故窗口内记录了事件。",
                "warning",
            )
        } else {
            return None;
        };
    Some((
        title,
        format!(
            "{} Provider={}，Event ID={}",
            description,
            fact.provider,
            event_id
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".into())
        ),
        severity,
    ))
}

fn sustained(
    samples: &[Sample],
    predicate: impl Fn(&Sample) -> bool,
    required: usize,
) -> Option<&Sample> {
    let mut count = 0;
    for sample in samples {
        if predicate(sample) {
            count += 1;
            if count >= required {
                return Some(sample);
            }
        } else {
            count = 0;
        }
    }
    None
}

pub(crate) fn deterministic_report(symptom_label: &str, observations: &[Observation]) -> Report {
    let actionable: Vec<_> = observations
        .iter()
        .filter(|item| item.severity != "info")
        .collect();
    if actionable.is_empty() {
        return Report {
            summary: format!(
                "{symptom_label}窗口内未发现超过内置阈值的性能或关键事件异常，现有证据不足以判断根因。"
            ),
            likely_causes: Vec::new(),
            next_tests: vec![
                Test {
                    title: "再次出现时立即标记".into(),
                    description: "积累多次事故后比较重复模式，避免基于单次样本猜测。".into(),
                    priority: 1,
                },
                Test {
                    title: "启用更高精度 WPR 采集".into(),
                    description: "若问题可复现，可用 ETW 进一步检查调度、DPC/ISR 与 I/O 延迟。".into(),
                    priority: 2,
                },
            ],
            generated_by: "deterministic-rules".into(),
        };
    }

    let causes = actionable
        .iter()
        .take(3)
        .enumerate()
        .map(|(index, item)| Cause {
            title: item.title.clone(),
            confidence: (0.78 - index as f64 * 0.1).max(0.5),
            explanation: item.description.clone(),
            supporting_evidence_ids: vec![item.id.clone()],
        })
        .collect();
    Report {
        summary: format!(
            "{symptom_label}前后发现 {} 项需要优先核查的异常；结论仅基于本地确定性证据。",
            actionable.len()
        ),
        likely_causes: causes,
        next_tests: vec![
            Test {
                title: "核对最高优先级证据".into(),
                description: "先检查时间上最接近触发点且严重度最高的观察结果。".into(),
                priority: 1,
            },
            Test {
                title: "比较历史事故".into(),
                description: "确认同一异常是否在多次事故前重复出现。".into(),
                priority: 2,
            },
        ],
        generated_by: "deterministic-rules".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(offset: i64) -> Sample {
        Sample {
            timestamp_ms: offset,
            timestamp: offset.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn detects_required_mvp_thresholds() {
        let mut first = sample(1_000);
        first.cpu_percent = 96.0;
        first.commit_percent = 94.0;
        first.disk_latency_ms = 820.0;
        first.disk_queue_length = 8.0;
        first.network_errors = 2;
        first.top_processes = vec![crate::collector::ProcessSample {
            pid: 42,
            name: "load.exe".into(),
            cpu_percent: 88.0,
            ..Default::default()
        }];
        let mut second = first.clone();
        second.timestamp_ms = 3_000;

        let result = extract(&[first, second], 4_000, "", "");
        let titles: Vec<_> = result.iter().map(|item| item.title.as_str()).collect();
        assert!(titles.contains(&"CPU 持续饱和"));
        assert!(titles.contains(&"内存 Commit 压力"));
        assert!(titles.contains(&"磁盘延迟严重升高"));
        assert!(titles.contains(&"磁盘队列持续积压"));
        assert!(titles.contains(&"网络接口错误或丢弃"));
        assert!(titles.contains(&"单进程 CPU 峰值"));
    }

    #[test]
    fn reports_insufficient_evidence_without_guessing() {
        let observations = extract(&[sample(1_000), sample(3_000)], 4_000, "", "");
        let report = deterministic_report("系统卡顿", &observations);
        assert!(report.likely_causes.is_empty());
        assert!(report.summary.contains("证据不足"));
    }

    #[test]
    fn extracts_critical_windows_events() {
        let observations = extract(
            &[],
            chrono::DateTime::parse_from_rfc3339("2026-07-03T15:20:14Z")
                .unwrap()
                .timestamp_millis(),
            "<Events><Event><System><Provider Name=\"WHEA-Logger\"/><EventID>18</EventID><TimeCreated SystemTime=\"2026-07-03T15:20:12Z\"/></System></Event></Events>",
            "",
        );
        assert_eq!(observations[0].severity, "critical");
        assert!(observations[0].title.contains("WHEA"));
        assert_eq!(observations[0].offset_ms, -2_000);
    }

    #[test]
    fn parses_rendered_windows_event_details() {
        let records = parse_windows_events(
            "<Events><Event><System><Provider Name=\"Application Error\"/><EventID>1000</EventID><Level>2</Level><TimeCreated SystemTime=\"2026-07-03T15:20:12Z\"/><Channel>Application</Channel><Computer>WORKSTATION</Computer></System><EventData><Data Name=\"AppName\">demo.exe</Data></EventData><RenderingInfo><Message>程序 &amp; 服务已停止工作。</Message></RenderingInfo></Event></Events>",
            "Application",
        );

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].provider, "Application Error");
        assert_eq!(records[0].event_id, Some(1000));
        assert_eq!(records[0].level, Some(2));
        assert_eq!(records[0].message, "程序 & 服务已停止工作。");
        assert_eq!(records[0].data, vec!["AppName: demo.exe"]);
    }
}
