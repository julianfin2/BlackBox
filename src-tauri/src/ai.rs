use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::{Incident, Observation, Report, Settings};

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    stream: bool,
    format: &'static str,
    messages: Vec<Message<'a>>,
    options: Options,
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'static str,
    content: &'a str,
}

#[derive(Serialize)]
struct Options {
    temperature: f32,
}

#[derive(Deserialize)]
struct ChatResponse {
    message: ChatMessage,
}

#[derive(Deserialize)]
struct ChatMessage {
    content: String,
}

pub(crate) async fn analyze(
    settings: &Settings,
    incident: &Incident,
    observations: &[Observation],
) -> Result<Report, String> {
    if settings.ai_mode != "ollama" {
        return Err("本地 AI 未启用".into());
    }
    if !is_local_endpoint(&settings.ollama_endpoint) {
        return Err("MVP 只允许连接 localhost、127.0.0.1 或 ::1 上的本地模型服务".into());
    }

    let evidence = serde_json::to_string_pretty(observations).map_err(|error| error.to_string())?;
    let prompt = format!(
        r#"你是 Windows 事故诊断解释器。你不能测量系统，只能解释提供的确定性证据。
事故：{}，严重程度：{}，触发时间：{}
证据：
{}

只输出 JSON，结构必须严格为：
{{
  "summary": "不夸大结论的中文摘要",
  "likely_causes": [{{
    "title": "原因标题",
    "confidence": 0.0,
    "explanation": "引用事实并区分推测",
    "supporting_evidence_ids": ["obs_001"]
  }}],
  "next_tests": [{{
    "title": "验证步骤",
    "description": "不自动执行任何系统修改",
    "priority": 1
  }}],
  "generated_by": "ollama:{}"
}}
规则：supporting_evidence_ids 只能使用输入中存在的 ID；证据不足时 likely_causes 必须为空；confidence 范围 0 到 1；不得建议自动修改驱动、注册表或安全设置。"#,
        incident.symptom_label,
        incident.severity,
        incident.trigger_time,
        evidence,
        settings.ollama_model
    );
    let url = format!(
        "{}/api/chat",
        settings.ollama_endpoint.trim_end_matches('/')
    );
    let response = reqwest::Client::new()
        .post(url)
        .timeout(std::time::Duration::from_secs(90))
        .json(&ChatRequest {
            model: &settings.ollama_model,
            stream: false,
            format: "json",
            messages: vec![Message {
                role: "user",
                content: &prompt,
            }],
            options: Options { temperature: 0.1 },
        })
        .send()
        .await
        .map_err(|error| format!("无法连接本地 Ollama：{error}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "Ollama 返回 HTTP {}：{}",
            response.status(),
            response.text().await.unwrap_or_default()
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > 1_048_576)
    {
        return Err("Ollama 响应超过 1 MB 安全上限".into());
    }
    let body = response
        .bytes()
        .await
        .map_err(|error| format!("读取 Ollama 响应失败：{error}"))?;
    if body.len() > 1_048_576 {
        return Err("Ollama 响应超过 1 MB 安全上限".into());
    }
    let result: ChatResponse =
        serde_json::from_slice(&body).map_err(|error| format!("Ollama 响应格式无效：{error}"))?;
    let mut report: Report = serde_json::from_str(&result.message.content)
        .map_err(|error| format!("模型未返回符合 Schema 的 JSON：{error}"))?;
    validate(&report, observations)?;
    report.generated_by = format!("ollama:{}", settings.ollama_model);
    Ok(report)
}

fn validate(report: &Report, observations: &[Observation]) -> Result<(), String> {
    if report.summary.trim().is_empty() || report.summary.chars().count() > 4_000 {
        return Err("模型摘要为空或超过长度上限".into());
    }
    if report.likely_causes.len() > 5 || report.next_tests.len() > 10 {
        return Err("模型返回的原因或验证步骤数量超过上限".into());
    }
    let ids: HashSet<_> = observations.iter().map(|item| item.id.as_str()).collect();
    for cause in &report.likely_causes {
        if cause.title.trim().is_empty() || cause.explanation.trim().is_empty() {
            return Err("模型返回了缺少标题或解释的原因".into());
        }
        if !(0.0..=1.0).contains(&cause.confidence) {
            return Err(format!("原因“{}”的可信度超出 0–1", cause.title));
        }
        if cause.supporting_evidence_ids.is_empty() {
            return Err(format!("原因“{}”没有引用证据", cause.title));
        }
        if let Some(id) = cause
            .supporting_evidence_ids
            .iter()
            .find(|id| !ids.contains(id.as_str()))
        {
            return Err(format!("模型引用了不存在的证据 ID：{id}"));
        }
    }
    if report
        .next_tests
        .iter()
        .any(|test| test.priority == 0 || test.title.trim().is_empty())
    {
        return Err("模型返回了无效的验证步骤".into());
    }
    Ok(())
}

pub(crate) fn is_local_endpoint(endpoint: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(endpoint) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_ai_endpoint_is_rejected() {
        assert!(is_local_endpoint("http://127.0.0.1:11434"));
        assert!(is_local_endpoint("http://localhost:11434"));
        assert!(!is_local_endpoint("https://api.example.com"));
        assert!(!is_local_endpoint("http://localhost.evil.example"));
        assert!(!is_local_endpoint("file://localhost/C:/secret"));
    }

    #[test]
    fn report_must_reference_existing_evidence() {
        let report = Report {
            summary: "test".into(),
            likely_causes: vec![crate::Cause {
                title: "test".into(),
                confidence: 0.8,
                explanation: "test".into(),
                supporting_evidence_ids: vec!["missing".into()],
            }],
            next_tests: Vec::new(),
            generated_by: "test".into(),
        };
        assert!(validate(&report, &[]).is_err());
    }
}
