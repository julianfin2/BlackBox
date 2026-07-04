use chrono::Utc;
use rusqlite::{params, Connection};
use std::path::Path;

use crate::{Incident, Observation, Report};

fn connect(root: &Path) -> Result<Connection, String> {
    Connection::open(root.join("blackbox.db")).map_err(|error| error.to_string())
}

pub(crate) fn initialize(root: &Path) -> Result<(), String> {
    let connection = connect(root)?;
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if version != 1 {
        connection
            .execute_batch(
                r#"
                PRAGMA foreign_keys = OFF;
                DROP TABLE IF EXISTS reports;
                DROP TABLE IF EXISTS observations;
                DROP TABLE IF EXISTS incidents;
                DROP TABLE IF EXISTS audit_events;
                "#,
            )
            .map_err(|error| error.to_string())?;
    }
    connection
        .execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                trigger_time TEXT NOT NULL,
                trigger_source TEXT NOT NULL,
                symptom TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                likely_cause TEXT,
                confidence REAL,
                sensitivity_level INTEGER NOT NULL,
                machine_id TEXT NOT NULL,
                app_version TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS observations (
                incident_id TEXT NOT NULL,
                observation_id TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (incident_id, observation_id),
                FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS reports (
                incident_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                details TEXT
            );
            PRAGMA user_version = 1;
            "#,
        )
        .map_err(|error| error.to_string())
}

pub(crate) fn upsert_incident(root: &Path, incident: &Incident) -> Result<(), String> {
    connect(root)?
        .execute(
            r#"
            INSERT INTO incidents (
                id, schema_version, created_at, trigger_time, trigger_source, symptom,
                severity, status, likely_cause, confidence, sensitivity_level, machine_id,
                app_version
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            ON CONFLICT(id) DO UPDATE SET
                status = excluded.status,
                likely_cause = excluded.likely_cause,
                confidence = excluded.confidence
            "#,
            params![
                incident.id,
                incident.schema_version,
                incident.created_at,
                incident.trigger_time,
                incident.trigger_source,
                incident.symptom,
                incident.severity,
                incident.status,
                incident.likely_cause,
                incident.confidence,
                incident.sensitivity_level,
                incident.machine_id,
                incident.app_version
            ],
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
}

pub(crate) fn replace_observations(
    root: &Path,
    incident_id: &str,
    observations: &[Observation],
) -> Result<(), String> {
    let mut connection = connect(root)?;
    let transaction = connection
        .transaction()
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "DELETE FROM observations WHERE incident_id = ?1",
            [incident_id],
        )
        .map_err(|error| error.to_string())?;
    for item in observations {
        let payload = serde_json::to_string(item).map_err(|error| error.to_string())?;
        transaction
            .execute(
                "INSERT INTO observations (incident_id, observation_id, category, severity, payload_json) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![incident_id, item.id, item.category, item.severity, payload],
            )
            .map_err(|error| error.to_string())?;
    }
    transaction.commit().map_err(|error| error.to_string())
}

pub(crate) fn save_report(root: &Path, incident_id: &str, report: &Report) -> Result<(), String> {
    let payload = serde_json::to_string(report).map_err(|error| error.to_string())?;
    connect(root)?
        .execute(
            r#"
            INSERT INTO reports (incident_id, payload_json, generated_at)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(incident_id) DO UPDATE SET
                payload_json = excluded.payload_json,
                generated_at = excluded.generated_at
            "#,
            params![incident_id, payload, Utc::now().to_rfc3339()],
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
}

pub(crate) fn delete_incident(root: &Path, incident_id: &str) -> Result<(), String> {
    connect(root)?
        .execute("DELETE FROM incidents WHERE id = ?1", [incident_id])
        .map(|_| ())
        .map_err(|error| error.to_string())
}

pub(crate) fn clear_incidents(root: &Path) -> Result<(), String> {
    connect(root)?
        .execute("DELETE FROM incidents", [])
        .map(|_| ())
        .map_err(|error| error.to_string())
}

pub(crate) fn clear_all_data(root: &Path) -> Result<(), String> {
    connect(root)?
        .execute_batch(
            "DELETE FROM reports;
             DELETE FROM observations;
             DELETE FROM incidents;
             DELETE FROM audit_events;
             VACUUM;",
        )
        .map_err(|error| error.to_string())
}

pub(crate) fn audit(
    root: &Path,
    action: &str,
    target: Option<&str>,
    details: Option<&str>,
) -> Result<(), String> {
    connect(root)?
        .execute(
            "INSERT INTO audit_events (timestamp, action, target, details) VALUES (?1, ?2, ?3, ?4)",
            params![Utc::now().to_rfc3339(), action, target, details],
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
}
