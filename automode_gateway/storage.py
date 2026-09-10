from __future__ import annotations

import json
import hashlib
import os
import re
import shutil
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .classifier import authorization_signals
from .dlp import BUILTIN_DETECTORS, redact_payload, scan_payload
from .evidence import decrypt as decrypt_evidence
from .evidence import encrypt as encrypt_evidence
from .evidence import load_key
from .llm_classifier import DEFAULT_PROMPTS
from .normalizer import extract_messages, normalize
from .review_context import build_review_context, normalize_tool_call
from .session_fingerprint import conversation_fingerprint as fingerprint_messages
from .session_fingerprint import messages_are_continuation


SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    external_session_id TEXT UNIQUE,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    client_type TEXT,
    protocols_json TEXT NOT NULL DEFAULT '[]',
    models_json TEXT NOT NULL DEFAULT '[]',
    call_count INTEGER NOT NULL DEFAULT 0,
    tool_call_count INTEGER NOT NULL DEFAULT 0,
    allow_count INTEGER NOT NULL DEFAULT 0,
    alert_count INTEGER NOT NULL DEFAULT 0,
    max_risk TEXT NOT NULL DEFAULT 'low',
    conversation_fingerprint TEXT,
    authorization_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS session_risk_segments (
    id TEXT PRIMARY KEY, session_id TEXT NOT NULL, trace_id TEXT NOT NULL,
    started_at TEXT NOT NULL, ended_at TEXT NOT NULL,
    purpose_risk TEXT NOT NULL, transfer_intent TEXT NOT NULL, severity TEXT NOT NULL,
    state TEXT NOT NULL, reason_code TEXT NOT NULL, summary TEXT NOT NULL,
    source TEXT NOT NULL, version TEXT NOT NULL, alert_id TEXT,
    FOREIGN KEY(session_id) REFERENCES sessions(id), FOREIGN KEY(trace_id) REFERENCES traces(id)
);
CREATE INDEX IF NOT EXISTS idx_session_risk_segments_session ON session_risk_segments(session_id, started_at);
CREATE TABLE IF NOT EXISTS traces (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    protocol TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    model TEXT,
    session_id TEXT,
    is_stream INTEGER NOT NULL,
    latest_user_text TEXT,
    declared_tool_count INTEGER NOT NULL DEFAULT 0,
    request_headers_json TEXT NOT NULL,
    request_body_json TEXT,
    response_status INTEGER,
    response_bytes INTEGER NOT NULL DEFAULT 0,
    latency_ms REAL,
    intent TEXT,
    speech_act TEXT,
    risk TEXT,
    decision TEXT,
    classification_json TEXT,
    error TEXT,
    correlation_status TEXT NOT NULL DEFAULT 'correlated'
);
CREATE INDEX IF NOT EXISTS idx_traces_created_at ON traces(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_traces_session_id ON traces(session_id, created_at);
CREATE TABLE IF NOT EXISTS tool_actions (
    id TEXT PRIMARY KEY, trace_id TEXT NOT NULL, phase TEXT NOT NULL,
    tool_name TEXT NOT NULL, arguments_json TEXT, capability TEXT NOT NULL,
    target TEXT, side_effect TEXT, risk TEXT, action_hash TEXT NOT NULL,
    created_at TEXT NOT NULL, FOREIGN KEY(trace_id) REFERENCES traces(id)
);
CREATE INDEX IF NOT EXISTS idx_tool_actions_trace ON tool_actions(trace_id);
CREATE TABLE IF NOT EXISTS classification_runs (
    id TEXT PRIMARY KEY, trace_id TEXT NOT NULL, review_transcript_json TEXT NOT NULL,
    final_decision TEXT NOT NULL, final_stage TEXT NOT NULL, risk TEXT NOT NULL,
    action_alignment TEXT NOT NULL, reason_code TEXT NOT NULL, reason TEXT NOT NULL,
    started_at TEXT NOT NULL, completed_at TEXT NOT NULL, total_latency_ms REAL NOT NULL,
    review_object TEXT NOT NULL DEFAULT 'tool_action',
    request_safety TEXT NOT NULL DEFAULT 'not_reviewed',
    request_purpose TEXT NOT NULL DEFAULT 'unknown',
    data_findings_json TEXT NOT NULL DEFAULT '[]',
    destination_json TEXT NOT NULL DEFAULT '{}',
    policy_decision TEXT NOT NULL DEFAULT 'allow',
    matched_policies_json TEXT NOT NULL DEFAULT '[]',
    evidence_id TEXT,
    identity_json TEXT NOT NULL DEFAULT '{}',
    semantic_status TEXT NOT NULL DEFAULT 'not_needed',
    rule_severity TEXT,
    llm_severity TEXT,
    llm_status TEXT,
    divergence INTEGER NOT NULL DEFAULT 0,
    hit_source TEXT,
    FOREIGN KEY(trace_id) REFERENCES traces(id)
);
CREATE TABLE IF NOT EXISTS classification_stages (
    id TEXT PRIMARY KEY, run_id TEXT NOT NULL, stage TEXT NOT NULL, status TEXT NOT NULL,
    model TEXT, input_hash TEXT, verdict TEXT NOT NULL, risk TEXT NOT NULL,
    reason_code TEXT NOT NULL, reason TEXT NOT NULL, matched_rule_ids_json TEXT NOT NULL,
    matched_rule_versions_json TEXT NOT NULL DEFAULT '[]', latency_ms REAL NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '[]', input_tokens INTEGER, output_tokens INTEGER, error_code TEXT,
    FOREIGN KEY(run_id) REFERENCES classification_runs(id)
);
CREATE INDEX IF NOT EXISTS idx_stages_run ON classification_stages(run_id);
CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, original_text TEXT NOT NULL,
    current_version INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 0,
    compiled_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rule_versions (
    id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, version INTEGER NOT NULL,
    original_text TEXT NOT NULL, compiled_json TEXT NOT NULL, created_at TEXT NOT NULL,
    UNIQUE(rule_id, version), FOREIGN KEY(rule_id) REFERENCES rules(id)
);
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY, trace_id TEXT, classification_run_id TEXT,
    session_record_id TEXT, created_at TEXT NOT NULL, severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open', reason_code TEXT NOT NULL, title TEXT NOT NULL,
    reason TEXT NOT NULL, evidence_json TEXT NOT NULL, actions_json TEXT NOT NULL,
    matched_rules_json TEXT NOT NULL, final_stage TEXT NOT NULL,
    evidence_id TEXT, data_findings_json TEXT NOT NULL DEFAULT '[]', destination_json TEXT NOT NULL DEFAULT '{}',
    acknowledged_at TEXT, operator_note TEXT, feedback TEXT,
    rule_severity TEXT, llm_severity TEXT, llm_status TEXT,
    review_status TEXT NOT NULL DEFAULT 'resolved',
    divergence INTEGER NOT NULL DEFAULT 0,
    hit_source TEXT,
    channel_source TEXT NOT NULL DEFAULT 'legacy', event_id TEXT,
    FOREIGN KEY(trace_id) REFERENCES traces(id)
);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_event_id ON alerts(event_id);
CREATE TABLE IF NOT EXISTS test_runs (
    id TEXT PRIMARY KEY, created_at TEXT NOT NULL, input_json TEXT NOT NULL,
    temporary_rule_json TEXT, result_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY, value_json TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY, created_at TEXT NOT NULL, action TEXT NOT NULL,
    entity_type TEXT NOT NULL, entity_id TEXT, detail_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS destinations (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, upstream_pattern TEXT NOT NULL,
    model_pattern TEXT NOT NULL, provider TEXT, region TEXT,
    trust TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dlp_policies (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, original_text TEXT NOT NULL,
    current_version INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 0,
    compiled_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dlp_policy_versions (
    id TEXT PRIMARY KEY, policy_id TEXT NOT NULL, version INTEGER NOT NULL,
    original_text TEXT NOT NULL, compiled_json TEXT NOT NULL, created_at TEXT NOT NULL,
    UNIQUE(policy_id, version), FOREIGN KEY(policy_id) REFERENCES dlp_policies(id)
);
CREATE TABLE IF NOT EXISTS encrypted_evidence (
    id TEXT PRIMARY KEY, trace_id TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
    nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, content_hash TEXT NOT NULL,
    categories_json TEXT NOT NULL, locations_json TEXT NOT NULL, destination_json TEXT NOT NULL,
    FOREIGN KEY(trace_id) REFERENCES traces(id)
);
CREATE INDEX IF NOT EXISTS idx_evidence_trace ON encrypted_evidence(trace_id);
CREATE INDEX IF NOT EXISTS idx_evidence_expiry ON encrypted_evidence(expires_at);
CREATE TABLE IF NOT EXISTS evidence_access_log (
    id TEXT PRIMARY KEY, evidence_id TEXT NOT NULL, accessed_at TEXT NOT NULL,
    actor TEXT NOT NULL, purpose TEXT NOT NULL, source TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sources (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    allow_trusted_identity INTEGER NOT NULL DEFAULT 0,
    rate_limit_per_minute INTEGER,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sources_token ON sources(token);
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    external_event_id TEXT,
    source_id TEXT NOT NULL,
    call_id TEXT NOT NULL,
    attempt_id TEXT,
    event_type TEXT NOT NULL,
    protocol TEXT NOT NULL,
    capture_stage TEXT NOT NULL,
    content_integrity TEXT NOT NULL,
    is_realtime INTEGER NOT NULL DEFAULT 1,
    timestamp TEXT NOT NULL,
    received_at TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    body_hash TEXT,
    disk_buffer_path TEXT,
    processing_status TEXT NOT NULL DEFAULT 'pending',
    association_status TEXT NOT NULL DEFAULT 'none',
    rule_status TEXT NOT NULL DEFAULT 'pending',
    llm_status TEXT NOT NULL DEFAULT 'pending',
    rule_verdict_json TEXT,
    llm_verdict_json TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    completed_at TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    response_evidence_json TEXT NOT NULL DEFAULT '[]',
    FOREIGN KEY(source_id) REFERENCES sources(id)
);
CREATE INDEX IF NOT EXISTS idx_events_call_id ON events(call_id);
CREATE INDEX IF NOT EXISTS idx_events_source_id ON events(source_id);
CREATE INDEX IF NOT EXISTS idx_events_status ON events(processing_status, rule_status, llm_status);
CREATE TABLE IF NOT EXISTS event_tasks (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    retry_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    error_message TEXT,
    FOREIGN KEY(event_id) REFERENCES events(id)
);
CREATE INDEX IF NOT EXISTS idx_event_tasks_stage_status ON event_tasks(stage, status);
CREATE INDEX IF NOT EXISTS idx_event_tasks_event_id ON event_tasks(event_id);
"""

TRACE_COLUMNS = {
    "session_record_id": "TEXT",
    "pipeline_status": "TEXT NOT NULL DEFAULT 'pending'",
    "final_decision": "TEXT",
    "final_stage": "TEXT",
    "final_reason_code": "TEXT",
    "final_reason": "TEXT",
    "session_evidence_json": "TEXT NOT NULL DEFAULT '{}'",
    "response_body_json": "TEXT",
    "response_content_type": "TEXT",
    "response_capture_complete": "INTEGER NOT NULL DEFAULT 1",
    "correlation_status": "TEXT NOT NULL DEFAULT 'correlated'",
}

STAGE_COLUMNS = {
    "matched_rule_versions_json": "TEXT NOT NULL DEFAULT '[]'",
    "evidence_json": "TEXT NOT NULL DEFAULT '[]'",
}

ALERT_COLUMNS = {
    "evidence_id": "TEXT",
    "data_findings_json": "TEXT NOT NULL DEFAULT '[]'",
    "destination_json": "TEXT NOT NULL DEFAULT '{}'",
    "rule_severity": "TEXT",
    "llm_severity": "TEXT",
    "llm_status": "TEXT",
    "review_status": "TEXT NOT NULL DEFAULT 'resolved'",
    "divergence": "INTEGER NOT NULL DEFAULT 0",
    "hit_source": "TEXT",
    "channel_source": "TEXT NOT NULL DEFAULT 'legacy'",
    "event_id": "TEXT",
}

RUN_COLUMNS = {
    "review_object": "TEXT NOT NULL DEFAULT 'tool_action'",
    "request_safety": "TEXT NOT NULL DEFAULT 'not_reviewed'",
    "request_purpose": "TEXT NOT NULL DEFAULT 'unknown'",
    "data_findings_json": "TEXT NOT NULL DEFAULT '[]'",
    "destination_json": "TEXT NOT NULL DEFAULT '{}'",
    "policy_decision": "TEXT NOT NULL DEFAULT 'allow'",
    "matched_policies_json": "TEXT NOT NULL DEFAULT '[]'",
    "evidence_id": "TEXT",
    "identity_json": "TEXT NOT NULL DEFAULT '{}'",
    "semantic_status": "TEXT NOT NULL DEFAULT 'not_needed'",
    "rule_severity": "TEXT",
    "llm_severity": "TEXT",
    "llm_status": "TEXT",
    "divergence": "INTEGER NOT NULL DEFAULT 0",
    "hit_source": "TEXT",
}

SESSION_COLUMNS = {
    "conversation_fingerprint": "TEXT",
    "authorization_json": "TEXT NOT NULL DEFAULT '{}'",
}

_RISK_ORDER = ["low", "medium", "high", "critical"]

SECRET_HEADERS = {
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "cookie",
    "set-cookie",
}


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        try:
            return bool(super().__exit__(exc_type, exc, traceback))
        finally:
            self.close()


class TraceStore:
    def __init__(self, path: str | Path, store_raw: bool = True, evidence_key: bytes | None = None) -> None:
        self.path = str(path)
        self.store_raw = store_raw
        self.evidence_key = evidence_key if evidence_key is not None else load_key(os.getenv("AUTOMODE_EVIDENCE_KEY_FILE"))
        self._initialize()
        self.purge_expired_evidence()

    def _connect(self) -> ClosingConnection:
        connection = sqlite3.connect(self.path, timeout=10, factory=ClosingConnection)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        database = Path(self.path)
        database.parent.mkdir(parents=True, exist_ok=True)
        backup: Path | None = None
        if database.exists() and database.stat().st_size:
            with closing(sqlite3.connect(database)) as connection:
                tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                trace_columns = {row[1] for row in connection.execute("PRAGMA table_info(traces)")} if "traces" in tables else set()
                stage_columns = {row[1] for row in connection.execute("PRAGMA table_info(classification_stages)")} if "classification_stages" in tables else set()
                run_columns = {row[1] for row in connection.execute("PRAGMA table_info(classification_runs)")} if "classification_runs" in tables else set()
                session_columns = {row[1] for row in connection.execute("PRAGMA table_info(sessions)")} if "sessions" in tables else set()
                alert_columns = {row[1] for row in connection.execute("PRAGMA table_info(alerts)")} if "alerts" in tables else set()
                event_columns = {row[1] for row in connection.execute("PRAGMA table_info(events)")} if "events" in tables else set()
            needs_migration = (
                (trace_columns and set(TRACE_COLUMNS) - trace_columns)
                or (stage_columns and set(STAGE_COLUMNS) - stage_columns)
                or (run_columns and set(RUN_COLUMNS) - run_columns)
                or (session_columns and set(SESSION_COLUMNS) - session_columns)
                or (alert_columns and set(ALERT_COLUMNS) - alert_columns)
                or (event_columns and {"external_event_id", "body_hash", "response_evidence_json"} - event_columns)
            )
            if needs_migration:
                backup = database.with_name(f"{database.name}.pre-automode-migration.bak")
                shutil.copy2(database, backup)
        try:
            with self._connect() as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.executescript(SCHEMA)
                event_columns = {row[1] for row in connection.execute("PRAGMA table_info(events)")}
                if "external_event_id" not in event_columns:
                    connection.execute("ALTER TABLE events ADD COLUMN external_event_id TEXT")
                if "body_hash" not in event_columns:
                    connection.execute("ALTER TABLE events ADD COLUMN body_hash TEXT")
                if "response_evidence_json" not in event_columns:
                    connection.execute("ALTER TABLE events ADD COLUMN response_evidence_json TEXT NOT NULL DEFAULT '[]'")
                # Events created by the first implementation used the external ID as
                # their primary key. Preserve that value as the compatibility alias.
                connection.execute(
                    "UPDATE events SET external_event_id=id WHERE external_event_id IS NULL OR external_event_id=''"
                )
                connection.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_events_source_external_id "
                    "ON events(source_id, external_event_id)"
                )
                for table, columns in (("traces", TRACE_COLUMNS), ("classification_stages", STAGE_COLUMNS), ("classification_runs", RUN_COLUMNS), ("sessions", SESSION_COLUMNS), ("alerts", ALERT_COLUMNS)):
                    existing = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
                    for name, definition in columns.items():
                        if name not in existing:
                            connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
                connection.execute("UPDATE alerts SET channel_source = 'legacy' WHERE channel_source IS NULL OR channel_source = ''")
        except Exception:
            if backup is not None:
                shutil.copy2(backup, database)
            raise

    def create(
        self,
        *,
        trace_id: str | None = None,
        protocol: str,
        method: str,
        path: str,
        payload: dict[str, Any],
        headers: dict[str, str],
        session_id: str | None,
        latest_user_text: str,
        declared_tool_count: int,
        session_evidence: dict[str, Any] | None = None,
        conversation_fingerprint: str | None = None,
        session_signals: dict[str, Any] | None = None,
    ) -> str:
        trace_id = trace_id or str(uuid.uuid4())
        created_at = _now()
        safe_headers = {
            key: ("[REDACTED]" if key.lower() in SECRET_HEADERS else value)
            for key, value in headers.items()
        }
        payload_messages = extract_messages(payload)
        fingerprint = conversation_fingerprint or fingerprint_messages(payload_messages)
        keyword_policies = self.list_dlp_policies(enabled_only=True)
        safe_payload = _sanitize_payload(redact_payload(payload, scan_payload(payload, keyword_policies)))
        latest_value = {"text": latest_user_text}
        safe_latest = redact_payload(latest_value, scan_payload(latest_value, keyword_policies))["text"]
        with self._connect() as connection:
            session_record_id = _upsert_session(
                connection,
                external_session_id=session_id,
                conversation_fingerprint=fingerprint,
                incoming_messages=payload_messages,
                fallback_id=f"trace:{trace_id}",
                created_at=created_at,
                protocol=protocol,
                model=payload.get("model"),
                client_type=_client_type(headers),
            )
            if session_signals:
                merged = _merge_authorization(connection, session_record_id, session_signals)
                connection.execute(
                    "UPDATE sessions SET authorization_json=? WHERE id=?",
                    (json.dumps(merged, ensure_ascii=False), session_record_id),
                )
            existing_trace = connection.execute("SELECT id, correlation_status FROM traces WHERE id=?", (trace_id,)).fetchone()
            if existing_trace is not None and existing_trace["correlation_status"] == "request_missing":
                connection.execute(
                    """UPDATE traces SET
                        protocol=?, method=?, path=?, model=?, session_id=?, is_stream=?,
                        latest_user_text=?, declared_tool_count=?, request_headers_json=?, request_body_json=?,
                        session_record_id=?, pipeline_status='pending', session_evidence_json=?,
                        correlation_status='correlated'
                    WHERE id=?""",
                    (
                        protocol,
                        method,
                        path,
                        payload.get("model"),
                        session_id,
                        int(bool(payload.get("stream"))),
                        safe_latest,
                        declared_tool_count,
                        json.dumps(safe_headers, ensure_ascii=False),
                        json.dumps(safe_payload, ensure_ascii=False) if self.store_raw else None,
                        session_record_id,
                        json.dumps(session_evidence or {"status": "missing", "selected": None, "candidates": []}, ensure_ascii=False),
                        trace_id,
                    ),
                )
                tool_count = connection.execute("SELECT COUNT(*) FROM tool_actions WHERE trace_id=?", (trace_id,)).fetchone()[0]
                if tool_count and session_record_id:
                    connection.execute("UPDATE sessions SET tool_call_count=tool_call_count+? WHERE id=?", (tool_count, session_record_id))
            else:
                connection.execute(
                    """INSERT INTO traces (
                        id, created_at, protocol, method, path, model, session_id, is_stream,
                        latest_user_text, declared_tool_count, request_headers_json, request_body_json,
                        session_record_id, pipeline_status, session_evidence_json, correlation_status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, 'correlated')""",
                    (
                        trace_id,
                        created_at,
                        protocol,
                        method,
                        path,
                        payload.get("model"),
                        session_id,
                        int(bool(payload.get("stream"))),
                        safe_latest,
                        declared_tool_count,
                        json.dumps(safe_headers, ensure_ascii=False),
                        json.dumps(safe_payload, ensure_ascii=False) if self.store_raw else None,
                        session_record_id,
                        json.dumps(session_evidence or {"status": "missing", "selected": None, "candidates": []}, ensure_ascii=False),
                    ),
                )
        return trace_id

    def set_classification(self, trace_id: str, result: dict[str, Any]) -> None:
        with self._connect() as connection:
            connection.execute(
                """UPDATE traces SET intent=?, speech_act=?, risk=?, decision=?, classification_json=?
                   WHERE id=?""",
                (
                    result.get("intent"),
                    result.get("speech_act"),
                    result.get("risk"),
                    result.get("decision"),
                    json.dumps(result, ensure_ascii=False),
                    trace_id,
                ),
            )

    def save_pipeline(self, trace_id: str, result: dict[str, Any]) -> tuple[str, str | None]:
        run_id = str(uuid.uuid4())
        completed_at = _now()
        started_at = completed_at
        alert_id: str | None = None
        with self._connect() as connection:
            trace = connection.execute(
                "SELECT session_record_id FROM traces WHERE id=?", (trace_id,)
            ).fetchone()
            if trace is None:
                raise KeyError("trace not found")
            connection.execute(
                """INSERT INTO classification_runs (
                    id, trace_id, review_transcript_json, final_decision, final_stage, risk,
                    action_alignment, reason_code, reason, started_at, completed_at, total_latency_ms,
                    review_object, request_safety, request_purpose, data_findings_json,
                    destination_json, policy_decision, matched_policies_json, evidence_id, identity_json, semantic_status,
                    rule_severity, llm_severity, llm_status, divergence, hit_source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id, trace_id, json.dumps(result.get("review_transcript", []), ensure_ascii=False),
                    result["final_decision"], result["final_stage"], result["risk"],
                    result["action_alignment"], result["reason_code"], _redact(result["reason"]),
                    started_at, completed_at, float(result.get("total_latency_ms", 0)),
                    result.get("review_object", "tool_action"), result.get("request_safety", "not_reviewed"),
                    result.get("request_purpose", "unknown"), json.dumps(result.get("data_findings", []), ensure_ascii=False),
                    json.dumps(result.get("destination", {}), ensure_ascii=False), result.get("policy_decision", result["final_decision"]),
                    json.dumps(result.get("matched_policies", []), ensure_ascii=False), result.get("evidence_id"),
                    json.dumps(result.get("identity", {}), ensure_ascii=False),
                    result.get("semantic_status", "not_needed"),
                    result.get("rule_severity"), result.get("llm_severity"), result.get("llm_status"),
                    int(bool(result.get("divergence"))), result.get("hit_source"),
                ),
            )
            for stage in result.get("stages", []):
                connection.execute(
                    """INSERT INTO classification_stages (
                        id, run_id, stage, status, model, input_hash, verdict, risk, reason_code,
                        reason, matched_rule_ids_json, matched_rule_versions_json, latency_ms,
                        evidence_json, input_tokens, output_tokens, error_code
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        str(uuid.uuid4()), run_id, stage["stage"], stage["status"], stage.get("model"),
                        stage.get("input_hash"), stage["verdict"], stage["risk"], stage["reason_code"],
                        _redact(stage["reason"]), json.dumps(stage.get("matched_rule_ids", [])),
                        json.dumps(stage.get("matched_rule_versions", [])), stage.get("latency_ms", 0),
                        json.dumps(stage.get("evidence", []), ensure_ascii=False),
                        stage.get("input_tokens"), stage.get("output_tokens"), stage.get("error_code"),
                    ),
                )
            for action in result.get("proposed_actions", []):
                action_json = json.dumps(action.get("arguments"), ensure_ascii=False, sort_keys=True)
                connection.execute(
                    """INSERT INTO tool_actions (
                        id, trace_id, phase, tool_name, arguments_json, capability, target,
                        side_effect, risk, action_hash, created_at
                    ) VALUES (?, ?, 'proposed', ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        str(uuid.uuid4()), trace_id, action.get("name", "unknown"), action_json,
                        action.get("capability", "unknown"), action.get("target"),
                        action.get("side_effect"), action.get("risk"), _sha256(action_json), completed_at,
                    ),
                )
            connection.execute(
                """UPDATE traces SET pipeline_status='completed', final_decision=?, final_stage=?,
                    final_reason_code=?, final_reason=?, risk=?, decision=?, classification_json=? WHERE id=?""",
                (
                    result["final_decision"], result["final_stage"], result["reason_code"],
                    _redact(result["reason"]), result["risk"], result["final_decision"],
                    json.dumps(_sanitize_payload(_without_reasoning(result)), ensure_ascii=False), trace_id,
                ),
            )
            session_id = trace["session_record_id"]
            if session_id:
                connection.execute(
                    """UPDATE sessions SET tool_call_count=tool_call_count+?,
                        allow_count=allow_count+?, alert_count=alert_count+?, max_risk=? WHERE id=?""",
                    (
                        len(result.get("proposed_actions", [])), int(result["final_decision"] == "allow"),
                        int(result["final_decision"] == "alert"),
                        _max_risk_sql(connection, session_id, result["risk"]), session_id,
                    ),
                )
            if result["final_decision"] == "alert":
                existing_alert = connection.execute(
                    "SELECT id, status, operator_note, acknowledged_at, feedback FROM alerts WHERE trace_id=?",
                    (trace_id,)
                ).fetchone()
                if existing_alert is not None:
                    alert_id = existing_alert["id"]
                    connection.execute(
                        """UPDATE alerts SET
                            classification_run_id=?, severity=?, reason_code=?, title=?, reason=?,
                            evidence_json=?, actions_json=?, matched_rules_json=?, final_stage=?,
                            evidence_id=?, data_findings_json=?, destination_json=?,
                            rule_severity=?, llm_severity=?, llm_status=?, review_status=?,
                            divergence=?, hit_source=?
                        WHERE id=?""",
                        (
                            run_id, result["risk"], result["reason_code"], _alert_title(result),
                            _redact(result["reason"]),
                            json.dumps(result.get("authorization_evidence", []), ensure_ascii=False),
                            json.dumps(result.get("proposed_actions", []), ensure_ascii=False),
                            json.dumps(result.get("matched_rules", []), ensure_ascii=False),
                            result["final_stage"], result.get("evidence_id"),
                            json.dumps(result.get("data_findings", []), ensure_ascii=False),
                            json.dumps(result.get("destination", {}), ensure_ascii=False),
                            result.get("rule_severity"), result.get("llm_severity"), result.get("llm_status"),
                            result.get("review_status", "resolved"), int(bool(result.get("divergence"))),
                            result.get("hit_source"),
                            alert_id,
                        ),
                    )
                else:
                    alert_id = str(uuid.uuid4())
                    connection.execute(
                        """INSERT INTO alerts (
                            id, trace_id, classification_run_id, session_record_id, created_at, severity,
                            reason_code, title, reason, evidence_json, actions_json, matched_rules_json, final_stage,
                            evidence_id, data_findings_json, destination_json,
                            rule_severity, llm_severity, llm_status, review_status, divergence, hit_source
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            alert_id, trace_id, run_id, session_id, completed_at, result["risk"],
                            result["reason_code"], _alert_title(result), _redact(result["reason"]),
                            json.dumps(result.get("authorization_evidence", []), ensure_ascii=False),
                            json.dumps(result.get("proposed_actions", []), ensure_ascii=False),
                            json.dumps(result.get("matched_rules", []), ensure_ascii=False), result["final_stage"], result.get("evidence_id"),
                            json.dumps(result.get("data_findings", []), ensure_ascii=False),
                            json.dumps(result.get("destination", {}), ensure_ascii=False),
                            result.get("rule_severity"), result.get("llm_severity"), result.get("llm_status"),
                            result.get("review_status", "resolved"), int(bool(result.get("divergence"))),
                            result.get("hit_source"),
                        ),
                    )
        return run_id, alert_id

    def project_event_analysis(self, event_id: str, result: dict[str, Any]) -> dict[str, Any]:
        """Project a proxy adapter event analysis onto its existing Trace.

        ``result`` is the same pipeline record produced by
        ``AnalysisEngine.pipeline_record`` (including ``final_*``, channel
        severities, ``stages``, findings, destination and evidence ID). The
        projection uses a deterministic run ID per event, so a rule-stage
        write followed by an LLM-stage write updates one run and one set of
        stages. It only links alerts already carrying ``event_id`` and never
        touches session-risk alerts. Session decision counts change only by
        the difference from the previously projected trace verdict.
        """
        internal_id = self.resolve_event_id(event_id)
        if internal_id is None:
            raise KeyError(f"event not found: {event_id}")
        if not isinstance(result, dict):
            raise TypeError("event analysis result must be an object")

        with self._connect() as connection:
            event = connection.execute("SELECT * FROM events WHERE id=?", (internal_id,)).fetchone()
            if event is None:
                raise KeyError(f"event not found: {event_id}")
            if event["source_id"] != "proxy-adapter":
                raise ValueError("event analysis projection requires source_id='proxy-adapter'")

            raw_metadata = json.loads(event["metadata_json"] or "{}")
            source_metadata = raw_metadata.get("source_metadata") if isinstance(raw_metadata, dict) else {}
            if not isinstance(source_metadata, dict):
                source_metadata = {}
            trace_id = source_metadata.get("trace_id") or raw_metadata.get("trace_id")
            if not isinstance(trace_id, str) or not trace_id:
                raise ValueError("proxy event metadata must include trace_id")
            trace = connection.execute("SELECT * FROM traces WHERE id=?", (trace_id,)).fetchone()
            if trace is None:
                raise KeyError(f"trace not found: {trace_id}")

            run_id = f"event-analysis:{internal_id}"
            completed_at = _now()
            final_decision = str(result.get("final_decision") or result.get("decision") or "review")
            final_stage = str(result.get("final_stage") or result.get("classifier_stage") or "rules")
            risk = str(result.get("risk") or "low")
            reason_code = str(result.get("reason_code") or "EVENT_ANALYSIS")
            reason = _redact(str(result.get("reason") or "Event analysis projected to trace"))
            stages = result.get("stages") if isinstance(result.get("stages"), list) else []
            review_transcript = result.get("review_transcript") if isinstance(result.get("review_transcript"), list) else []
            values = (
                run_id, trace_id, json.dumps(_sanitize_projection(review_transcript), ensure_ascii=False),
                final_decision, final_stage, risk,
                str(result.get("action_alignment") or "unknown"), reason_code, reason,
                completed_at, completed_at, float(result.get("total_latency_ms") or 0),
                str(result.get("review_object") or "outbound_request"),
                str(result.get("request_safety") or "not_reviewed"),
                str(result.get("request_purpose") or "unknown"),
                json.dumps(_sanitize_projection(result.get("data_findings") or []), ensure_ascii=False),
                json.dumps(_sanitize_projection(result.get("destination") or {}), ensure_ascii=False),
                str(result.get("policy_decision") or final_decision),
                json.dumps(_sanitize_projection(result.get("matched_policies") or result.get("matched_rules") or []), ensure_ascii=False),
                result.get("evidence_id"), json.dumps(_sanitize_projection(result.get("identity") or {}), ensure_ascii=False),
                str(result.get("semantic_status") or result.get("review_status") or "not_needed"),
                result.get("rule_severity"), result.get("llm_severity"), str(result.get("llm_status") or "not_needed"),
                int(bool(result.get("divergence"))), result.get("hit_source"),
            )
            run_exists = connection.execute("SELECT id FROM classification_runs WHERE id=?", (run_id,)).fetchone()
            if run_exists is None:
                connection.execute(
                    """INSERT INTO classification_runs (
                        id, trace_id, review_transcript_json, final_decision, final_stage, risk,
                        action_alignment, reason_code, reason, started_at, completed_at, total_latency_ms,
                        review_object, request_safety, request_purpose, data_findings_json,
                        destination_json, policy_decision, matched_policies_json, evidence_id, identity_json, semantic_status,
                        rule_severity, llm_severity, llm_status, divergence, hit_source
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    values,
                )
            else:
                connection.execute(
                    """UPDATE classification_runs SET
                        trace_id=?, review_transcript_json=?, final_decision=?, final_stage=?, risk=?,
                        action_alignment=?, reason_code=?, reason=?, completed_at=?, total_latency_ms=?,
                        review_object=?, request_safety=?, request_purpose=?, data_findings_json=?,
                        destination_json=?, policy_decision=?, matched_policies_json=?, evidence_id=?, identity_json=?, semantic_status=?,
                        rule_severity=?, llm_severity=?, llm_status=?, divergence=?, hit_source=?
                       WHERE id=?""",
                    values[1:9] + values[10:] + (run_id,),
                )

            for index, stage in enumerate(stages):
                if not isinstance(stage, dict):
                    continue
                stage_id = f"{run_id}:stage:{index}"
                stage_values = (
                    stage_id, run_id, str(stage.get("stage") or "rules"), str(stage.get("status") or "completed"),
                    stage.get("model"), stage.get("input_hash"), str(stage.get("verdict") or "unknown"),
                    str(stage.get("risk") or "low"), str(stage.get("reason_code") or reason_code),
                    _redact(str(stage.get("reason") or reason)),
                    json.dumps(_sanitize_projection(stage.get("matched_rule_ids") or []), ensure_ascii=False),
                    json.dumps(_sanitize_projection(stage.get("matched_rule_versions") or []), ensure_ascii=False),
                    float(stage.get("latency_ms") or 0), json.dumps(_sanitize_projection(stage.get("evidence") or []), ensure_ascii=False),
                    stage.get("input_tokens"), stage.get("output_tokens"), stage.get("error_code"),
                )
                if connection.execute("SELECT id FROM classification_stages WHERE id=?", (stage_id,)).fetchone() is None:
                    connection.execute(
                        """INSERT INTO classification_stages (
                            id, run_id, stage, status, model, input_hash, verdict, risk, reason_code,
                            reason, matched_rule_ids_json, matched_rule_versions_json, latency_ms,
                            evidence_json, input_tokens, output_tokens, error_code
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        stage_values,
                    )
                else:
                    connection.execute(
                        """UPDATE classification_stages SET stage=?, status=?, model=?, input_hash=?, verdict=?, risk=?,
                           reason_code=?, reason=?, matched_rule_ids_json=?, matched_rule_versions_json=?, latency_ms=?,
                           evidence_json=?, input_tokens=?, output_tokens=?, error_code=? WHERE id=?""",
                        stage_values[2:] + (stage_id,),
                    )

            trace_summary = _sanitize_projection({
                **result,
                "trace_id": trace_id,
                "event_id": internal_id,
                "run_id": run_id,
            })
            connection.execute(
                """UPDATE traces SET pipeline_status=?, final_decision=?, final_stage=?,
                    final_reason_code=?, final_reason=?, risk=?, decision=?, classification_json=? WHERE id=?""",
                ("processing" if result.get("llm_status") in {"pending", "processing"} else "completed",
                 final_decision, final_stage, reason_code, reason, risk, final_decision,
                 json.dumps(trace_summary, ensure_ascii=False), trace_id),
            )
            if trace["session_record_id"]:
                previous = trace["final_decision"]
                connection.execute(
                    "UPDATE sessions SET allow_count=allow_count+?, alert_count=alert_count+?, max_risk=? WHERE id=?",
                    (
                        int(final_decision == "allow") - int(previous == "allow"),
                        int(final_decision == "alert") - int(previous == "alert"),
                        _max_risk_sql(connection, trace["session_record_id"], risk),
                        trace["session_record_id"],
                    ),
                )

            alert_rows = connection.execute(
                "SELECT id FROM alerts WHERE event_id=? ORDER BY created_at ASC", (internal_id,)
            ).fetchall()
            for alert in alert_rows:
                # Link only event alerts. Existing status, acknowledgement,
                # operator note and feedback are deliberately untouched.
                connection.execute(
                    "UPDATE alerts SET trace_id=?, session_record_id=?, classification_run_id=? WHERE id=?",
                    (trace_id, trace["session_record_id"], run_id, alert["id"]),
                )

        return {
            "event_id": internal_id,
            "trace_id": trace_id,
            "run_id": run_id,
            "session_record_id": trace["session_record_id"],
            "alert_ids": [str(row["id"]) for row in alert_rows],
        }

    def create_immediate_rule_alert(self, trace_id: str, rule_result: dict[str, Any]) -> str:
        created_at = _now()
        with self._connect() as connection:
            trace = connection.execute(
                "SELECT session_record_id FROM traces WHERE id=?", (trace_id,)
            ).fetchone()
            session_id = trace["session_record_id"] if trace else None
            existing = connection.execute(
                "SELECT id FROM alerts WHERE trace_id=?", (trace_id,)
            ).fetchone()
            if existing is not None:
                return str(existing["id"])
            alert_id = str(uuid.uuid4())
            run_id = rule_result.get("run_id") or str(uuid.uuid4())
            rule_sev = rule_result.get("rule_severity") or "high"
            connection.execute(
                """INSERT INTO alerts (
                    id, trace_id, classification_run_id, session_record_id, created_at, severity,
                    reason_code, title, reason, evidence_json, actions_json, matched_rules_json, final_stage,
                    evidence_id, data_findings_json, destination_json,
                    rule_severity, llm_severity, llm_status, review_status, divergence, hit_source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    alert_id, trace_id, run_id, session_id, created_at, rule_sev,
                    rule_result.get("reason_code", "RULE_MATCH"), _alert_title(rule_result),
                    _redact(rule_result.get("reason", "Outbound rule matched")),
                    json.dumps(rule_result.get("authorization_evidence", []), ensure_ascii=False),
                    json.dumps(rule_result.get("proposed_actions", []), ensure_ascii=False),
                    json.dumps(rule_result.get("matched_rules", []), ensure_ascii=False),
                    "rules", rule_result.get("evidence_id"),
                    json.dumps(rule_result.get("data_findings", []), ensure_ascii=False),
                    json.dumps(rule_result.get("destination", {}), ensure_ascii=False),
                    rule_sev, None, rule_result.get("llm_status", "pending"),
                    rule_result.get("review_status", "pending"), 0, "rule_only",
                ),
            )
            connection.execute(
                """UPDATE traces SET pipeline_status='processing', final_decision='alert', final_stage='rules',
                    final_reason_code=?, final_reason=?, risk=?, decision='alert' WHERE id=?""",
                (
                    rule_result.get("reason_code", "RULE_MATCH"),
                    _redact(rule_result.get("reason", "Outbound rule matched")),
                    rule_sev, trace_id,
                ),
            )
            return alert_id

    def record_orphan_response(
        self,
        trace_id: str,
        protocol: str = "openai_chat_completions",
        tool_calls: list[dict[str, Any]] | None = None,
        status: int | None = None,
        response_bytes: int = 0,
        latency_ms: float | None = None,
        error: str | None = None,
        response_capture_complete: bool = True,
    ) -> None:
        created_at = _now()
        with self._connect() as connection:
            existing = connection.execute("SELECT id FROM traces WHERE id=?", (trace_id,)).fetchone()
            if existing is None:
                connection.execute(
                    """INSERT INTO traces (
                        id, created_at, protocol, method, path, model, session_id, is_stream,
                        latest_user_text, declared_tool_count, request_headers_json, request_body_json,
                        response_status, response_bytes, latency_ms, error, pipeline_status,
                        correlation_status, response_capture_complete
                    ) VALUES (?, ?, ?, 'UNKNOWN', '/unknown', NULL, NULL, 0, '', 0, '{}', NULL, ?, ?, ?, ?, 'completed', 'request_missing', ?)""",
                    (trace_id, created_at, protocol, status, response_bytes, latency_ms, error, int(response_capture_complete)),
                )
        if tool_calls:
            self.record_tool_actions(trace_id, tool_calls)

    def record_tool_actions(self, trace_id: str, calls: list[dict[str, Any]]) -> None:
        """Persist response tool calls as evidence without making them the review object."""
        actions = [normalize_tool_call(call, source="response").to_dict() for call in calls]
        if not actions:
            return
        created_at = _now()
        with self._connect() as connection:
            trace = connection.execute("SELECT session_record_id FROM traces WHERE id=?", (trace_id,)).fetchone()
            if trace is None:
                raise KeyError("trace not found")
            existing = {
                row[0] for row in connection.execute("SELECT action_hash FROM tool_actions WHERE trace_id=?", (trace_id,))
            }
            inserted = 0
            for action in actions:
                action_json = json.dumps(action.get("arguments"), ensure_ascii=False, sort_keys=True)
                action_hash = _sha256(f"{action.get('name')}:{action_json}")
                if action_hash in existing:
                    continue
                connection.execute(
                    """INSERT INTO tool_actions (
                        id, trace_id, phase, tool_name, arguments_json, capability, target,
                        side_effect, risk, action_hash, created_at
                    ) VALUES (?, ?, 'proposed', ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        str(uuid.uuid4()), trace_id, action.get("name", "unknown"), action_json,
                        action.get("capability", "unknown"), action.get("target"),
                        action.get("side_effect"), action.get("risk"), action_hash, created_at,
                    ),
                )
                inserted += 1
            if inserted and trace["session_record_id"]:
                connection.execute(
                    "UPDATE sessions SET tool_call_count=tool_call_count+? WHERE id=?",
                    (inserted, trace["session_record_id"]),
                )

    def tool_actions(self, trace_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM tool_actions WHERE trace_id=? ORDER BY created_at",
                (trace_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    def record_event_tool_actions(self, event_id: str, calls: list[dict[str, Any]]) -> None:
        """Persist redacted response tool-call corroboration exactly once."""
        internal_id = self.resolve_event_id(event_id) or event_id
        safe_calls = _sanitize_event_metadata(calls or [])
        if not isinstance(safe_calls, list):
            safe_calls = []
        with self._connect() as connection:
            row = connection.execute(
                "SELECT response_evidence_json FROM events WHERE id=?", (internal_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"event not found: {event_id}")
            try:
                existing = json.loads(row["response_evidence_json"] or "[]")
            except (TypeError, json.JSONDecodeError):
                existing = []
            if not isinstance(existing, list):
                existing = []
            known = {
                _sha256(json.dumps(item, ensure_ascii=False, sort_keys=True))
                for item in existing
            }
            for item in safe_calls:
                digest = _sha256(json.dumps(item, ensure_ascii=False, sort_keys=True))
                if digest not in known:
                    existing.append(item)
                    known.add(digest)
            connection.execute(
                "UPDATE events SET response_evidence_json=? WHERE id=?",
                (json.dumps(existing, ensure_ascii=False), internal_id),
            )

    record_event_response_evidence = record_event_tool_actions
    record_event_tool_calls = record_event_tool_actions

    # Session user-intent risk -----------------------------------------------
    def session_risk_summary(self, session_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM session_risk_segments WHERE session_id=? ORDER BY ended_at DESC, rowid DESC LIMIT 1",
                (session_id,),
            ).fetchone()
        return _session_risk_row(row) if row else None

    def session_risk_segments(self, session_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM session_risk_segments WHERE session_id=? ORDER BY started_at, rowid",
                (session_id,),
            ).fetchall()
        return [_session_risk_row(row) for row in rows]

    def record_session_risk(self, trace_id: str, assessment: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
        """Store only derived risk fields.  Raw reviewer input never reaches SQLite."""
        now = _now()
        with self._connect() as connection:
            trace = connection.execute("SELECT session_record_id FROM traces WHERE id=?", (trace_id,)).fetchone()
            if trace is None or not trace["session_record_id"]:
                raise KeyError("trace session not found")
            session_id = trace["session_record_id"]
            previous = connection.execute(
                "SELECT * FROM session_risk_segments WHERE session_id=? ORDER BY ended_at DESC, rowid DESC LIMIT 1",
                (session_id,),
            ).fetchone()
            values = {
                "purpose_risk": str(assessment["purpose_risk"]), "transfer_intent": str(assessment["transfer_intent"]),
                "severity": str(assessment["severity"]), "state": str(assessment["state"]),
                "reason_code": str(assessment["reason_code"])[:80], "summary": _redact(str(assessment["summary"]))[:300],
                "source": str(assessment["source"]), "version": str(assessment.get("version", "session-risk-v1")),
            }
            same = previous and all(previous[key] == values[key] for key in ("purpose_risk", "transfer_intent", "severity", "state", "reason_code", "source", "version"))
            if same:
                connection.execute("UPDATE session_risk_segments SET ended_at=?, trace_id=? WHERE id=?", (now, trace_id, previous["id"]))
                segment_id = previous["id"]
            else:
                segment_id = str(uuid.uuid4())
                connection.execute(
                    """INSERT INTO session_risk_segments (
                        id, session_id, trace_id, started_at, ended_at, purpose_risk, transfer_intent,
                        severity, state, reason_code, summary, source, version, alert_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)""",
                    (segment_id, session_id, trace_id, now, now, values["purpose_risk"], values["transfer_intent"], values["severity"], values["state"], values["reason_code"], values["summary"], values["source"], values["version"]),
                )

            alert_id: str | None = None
            previous_severity = previous["severity"] if previous and previous["severity"] in _RISK_ORDER else "low"
            changed_category = bool(previous and (previous["purpose_risk"] != values["purpose_risk"] or previous["transfer_intent"] != values["transfer_intent"]))
            should_alert = values["severity"] in {"high", "critical"} and (not previous or _RISK_ORDER.index(values["severity"]) > _RISK_ORDER.index(previous_severity) or changed_category)
            if should_alert:
                alert_id = str(uuid.uuid4())
                connection.execute(
                    """INSERT INTO alerts (
                        id, trace_id, classification_run_id, session_record_id, created_at, severity,
                        reason_code, title, reason, evidence_json, actions_json, matched_rules_json,
                        final_stage, evidence_id, data_findings_json, destination_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', '[]', '[]', 'session_risk', NULL, '[]', '{}')""",
                    (alert_id, trace_id, f"session-risk:{segment_id}", session_id, now, values["severity"], values["reason_code"], f"{values['severity'].upper()}: session user-intent risk", values["summary"]),
                )
                connection.execute("UPDATE session_risk_segments SET alert_id=? WHERE id=?", (alert_id, segment_id))
                connection.execute("UPDATE sessions SET alert_count=alert_count+1, max_risk=? WHERE id=?", (_max_risk_sql(connection, session_id, values["severity"]), session_id))
            _audit(connection, "session_risk.recorded", "session", session_id, {"segment_id": segment_id, "severity": values["severity"], "alert": bool(alert_id)})
            row = connection.execute("SELECT * FROM session_risk_segments WHERE id=?", (segment_id,)).fetchone()
        assert row is not None
        return _session_risk_row(row), alert_id

    def finish(
        self,
        trace_id: str,
        *,
        status: int | None,
        response_bytes: int,
        latency_ms: float,
        error: str | None = None,
        response_body: bytes | None = None,
        response_content_type: str = "",
        response_capture_complete: bool = True,
    ) -> None:
        recorded_response = _record_response_body(response_body, response_content_type, response_capture_complete) if self.store_raw else None
        with self._connect() as connection:
            connection.execute(
                """UPDATE traces SET response_status=?, response_bytes=?, latency_ms=?, error=?,
                   response_body_json=?, response_content_type=?, response_capture_complete=?
                   WHERE id=?""",
                (status, response_bytes, latency_ms, error, json.dumps(recorded_response, ensure_ascii=False) if recorded_response is not None else None, response_content_type, int(response_capture_complete), trace_id),
            )

    def enabled_rules(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT compiled_json FROM rules WHERE enabled=1 ORDER BY updated_at DESC"
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def create_rule(self, compiled: dict[str, Any], *, confirmed: bool = False) -> dict[str, Any]:
        validate_rule(compiled)
        if compiled["effect"] == "always_alert" and not confirmed:
            raise ValueError("always_alert requires explicit confirmation")
        rule_id = str(compiled.get("id") or uuid.uuid4())
        now = _now()
        version = 1
        value = {**compiled, "id": rule_id, "version": version, "enabled": False}
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO rules VALUES (?, ?, ?, ?, 0, ?, ?, ?)",
                (rule_id, value["name"], value["original_text"], version, json.dumps(value, ensure_ascii=False), now, now),
            )
            connection.execute(
                "INSERT INTO rule_versions VALUES (?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), rule_id, version, value["original_text"], json.dumps(value, ensure_ascii=False), now),
            )
            _audit(connection, "rule.created", "rule", rule_id, {"version": version})
        return value

    def update_rule(self, rule_id: str, compiled: dict[str, Any], *, confirmed: bool = False) -> dict[str, Any]:
        validate_rule(compiled)
        if compiled["effect"] == "always_alert" and not confirmed:
            raise ValueError("always_alert requires explicit confirmation")
        now = _now()
        with self._connect() as connection:
            row = connection.execute("SELECT current_version, enabled FROM rules WHERE id=?", (rule_id,)).fetchone()
            if row is None:
                raise KeyError("rule not found")
            version = row["current_version"] + 1
            value = {**compiled, "id": rule_id, "version": version, "enabled": bool(row["enabled"])}
            connection.execute(
                """UPDATE rules SET name=?, original_text=?, current_version=?, compiled_json=?, updated_at=?
                   WHERE id=?""",
                (value["name"], value["original_text"], version, json.dumps(value, ensure_ascii=False), now, rule_id),
            )
            connection.execute(
                "INSERT INTO rule_versions VALUES (?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), rule_id, version, value["original_text"], json.dumps(value, ensure_ascii=False), now),
            )
            _audit(connection, "rule.updated", "rule", rule_id, {"version": version})
        return value

    def list_rules(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM rules ORDER BY updated_at DESC").fetchall()
        return [_rule_row(row) for row in rows]

    def get_rule(self, rule_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM rules WHERE id=?", (rule_id,)).fetchone()
        return _rule_row(row) if row else None

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> dict[str, Any]:
        with self._connect() as connection:
            if connection.execute("SELECT 1 FROM rules WHERE id=?", (rule_id,)).fetchone() is None:
                raise KeyError("rule not found")
            connection.execute("UPDATE rules SET enabled=?, updated_at=? WHERE id=?", (int(enabled), _now(), rule_id))
            _audit(connection, "rule.enabled" if enabled else "rule.disabled", "rule", rule_id, {})
        value = self.get_rule(rule_id)
        assert value is not None
        return value

    def delete_rule(self, rule_id: str) -> None:
        with self._connect() as connection:
            connection.execute("UPDATE rules SET enabled=0, updated_at=? WHERE id=?", (_now(), rule_id))
            _audit(connection, "rule.deleted", "rule", rule_id, {})

    def rule_versions(self, rule_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT version, original_text, compiled_json, created_at FROM rule_versions WHERE rule_id=? ORDER BY version DESC",
                (rule_id,),
            ).fetchall()
        return [{**json.loads(row["compiled_json"]), "created_at": row["created_at"]} for row in rows]

    def rollback_rule(self, rule_id: str, version: int) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT compiled_json FROM rule_versions WHERE rule_id=? AND version=?", (rule_id, version)
            ).fetchone()
            if row is None:
                raise KeyError("rule version not found")
        value = json.loads(row["compiled_json"])
        value.pop("id", None)
        value.pop("version", None)
        value.pop("enabled", None)
        result = self.update_rule(rule_id, value, confirmed=True)
        with self._connect() as connection:
            _audit(connection, "rule.rolled_back", "rule", rule_id, {"source_version": version, "new_version": result["version"]})
        return result

    # Shadow DLP target registry -------------------------------------------------
    def list_destinations(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM destinations ORDER BY updated_at DESC").fetchall()
        return [{**dict(row), "enabled": bool(row["enabled"])} for row in rows]

    def create_destination(self, value: dict[str, Any]) -> dict[str, Any]:
        _validate_destination(value)
        destination_id = str(value.get("id") or uuid.uuid4())
        now = _now()
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO destinations (
                    id, name, upstream_pattern, model_pattern, provider, region, trust, enabled, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (destination_id, value["name"], value.get("upstream_pattern", "*"), value.get("model_pattern", "*"),
                 value.get("provider"), value.get("region"), value["trust"], int(value.get("enabled", True)), now, now),
            )
            _audit(connection, "destination.created", "destination", destination_id, {"trust": value["trust"]})
        return self.get_destination(destination_id) or {}

    def get_destination(self, destination_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM destinations WHERE id=?", (destination_id,)).fetchone()
        return {**dict(row), "enabled": bool(row["enabled"])} if row else None

    def update_destination(self, destination_id: str, value: dict[str, Any]) -> dict[str, Any]:
        current = self.get_destination(destination_id)
        if current is None:
            raise KeyError("destination not found")
        merged = {**current, **value}
        _validate_destination(merged)
        with self._connect() as connection:
            connection.execute(
                """UPDATE destinations SET name=?, upstream_pattern=?, model_pattern=?, provider=?, region=?,
                   trust=?, enabled=?, updated_at=? WHERE id=?""",
                (merged["name"], merged.get("upstream_pattern", "*"), merged.get("model_pattern", "*"),
                 merged.get("provider"), merged.get("region"), merged["trust"], int(merged.get("enabled", True)), _now(), destination_id),
            )
            _audit(connection, "destination.updated", "destination", destination_id, {"trust": merged["trust"]})
        return self.get_destination(destination_id) or {}

    def delete_destination(self, destination_id: str) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM destinations WHERE id=?", (destination_id,))
            _audit(connection, "destination.deleted", "destination", destination_id, {})

    # Independent outbound-data policies ---------------------------------------
    def list_dlp_policies(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        query = "SELECT * FROM dlp_policies" + (" WHERE enabled=1" if enabled_only else "") + " ORDER BY updated_at DESC"
        with self._connect() as connection:
            rows = connection.execute(query).fetchall()
        return [_dlp_policy_row(row) for row in rows]

    def create_dlp_policy(self, compiled: dict[str, Any], enabled: bool = False) -> dict[str, Any]:
        _validate_dlp_policy(compiled)
        policy_id, version, now = str(compiled.get("id") or uuid.uuid4()), 1, _now()
        value = {**compiled, "id": policy_id, "version": version, "enabled": bool(enabled)}
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO dlp_policies VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (policy_id, value["name"], value["original_text"], version, int(enabled), json.dumps(value, ensure_ascii=False), now, now),
            )
            connection.execute(
                "INSERT INTO dlp_policy_versions VALUES (?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), policy_id, version, value["original_text"], json.dumps(value, ensure_ascii=False), now),
            )
            _audit(connection, "dlp_policy.created", "dlp_policy", policy_id, {"version": version})
        return self.get_dlp_policy(policy_id) or {}

    def get_dlp_policy(self, policy_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM dlp_policies WHERE id=?", (policy_id,)).fetchone()
        return _dlp_policy_row(row) if row else None

    def update_dlp_policy(self, policy_id: str, compiled: dict[str, Any]) -> dict[str, Any]:
        _validate_dlp_policy(compiled)
        current = self.get_dlp_policy(policy_id)
        if current is None:
            raise KeyError("DLP policy not found")
        version, now = int(current["version"]) + 1, _now()
        value = {**compiled, "id": policy_id, "version": version, "enabled": current["enabled"]}
        with self._connect() as connection:
            connection.execute(
                "UPDATE dlp_policies SET name=?, original_text=?, current_version=?, compiled_json=?, updated_at=? WHERE id=?",
                (value["name"], value["original_text"], version, json.dumps(value, ensure_ascii=False), now, policy_id),
            )
            connection.execute(
                "INSERT INTO dlp_policy_versions VALUES (?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), policy_id, version, value["original_text"], json.dumps(value, ensure_ascii=False), now),
            )
            _audit(connection, "dlp_policy.updated", "dlp_policy", policy_id, {"version": version})
        return self.get_dlp_policy(policy_id) or {}

    def set_dlp_policy_enabled(self, policy_id: str, enabled: bool) -> dict[str, Any]:
        with self._connect() as connection:
            if connection.execute("SELECT 1 FROM dlp_policies WHERE id=?", (policy_id,)).fetchone() is None:
                raise KeyError("DLP policy not found")
            connection.execute("UPDATE dlp_policies SET enabled=?, updated_at=? WHERE id=?", (int(enabled), _now(), policy_id))
            _audit(connection, "dlp_policy.enabled" if enabled else "dlp_policy.disabled", "dlp_policy", policy_id, {})
        return self.get_dlp_policy(policy_id) or {}

    def delete_dlp_policy(self, policy_id: str) -> None:
        with self._connect() as connection:
            connection.execute("UPDATE dlp_policies SET enabled=0, updated_at=? WHERE id=?", (_now(), policy_id))
            _audit(connection, "dlp_policy.deleted", "dlp_policy", policy_id, {})

    def dlp_policy_versions(self, policy_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT version, compiled_json, created_at FROM dlp_policy_versions WHERE policy_id=? ORDER BY version DESC", (policy_id,)
            ).fetchall()
        return [{**json.loads(row["compiled_json"]), "created_at": row["created_at"]} for row in rows]

    # Encrypted raw evidence ----------------------------------------------------
    def store_evidence(self, trace_id: str, payload: dict[str, Any], findings: list[dict[str, Any]], destination: dict[str, Any]) -> str | None:
        if not findings or self.evidence_key is None:
            return None
        evidence_id, created_at = str(uuid.uuid4()), _now()
        expires_at = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        nonce, ciphertext = encrypt_evidence(self.evidence_key, raw, trace_id.encode())
        categories = sorted({str(item.get("category")) for item in findings})
        locations = sorted({str(item.get("path")) for item in findings})
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO encrypted_evidence (
                    id, trace_id, created_at, expires_at, nonce, ciphertext, content_hash,
                    categories_json, locations_json, destination_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (evidence_id, trace_id, created_at, expires_at, nonce, ciphertext, hashlib.sha256(raw).hexdigest(),
                 json.dumps(categories), json.dumps(locations), json.dumps(destination, ensure_ascii=False)),
            )
        return evidence_id

    def evidence(self, evidence_id: str, *, actor: str, purpose: str, source: str) -> dict[str, Any]:
        if self.evidence_key is None:
            raise RuntimeError("evidence encryption key is not configured")
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM encrypted_evidence WHERE id=?", (evidence_id,)).fetchone()
            if row is None:
                raise KeyError("evidence not found")
            if row["expires_at"] <= _now():
                raise KeyError("evidence expired")
            plaintext = decrypt_evidence(self.evidence_key, row["nonce"], row["ciphertext"], row["trace_id"].encode())
            connection.execute(
                "INSERT INTO evidence_access_log VALUES (?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), evidence_id, _now(), actor[:200], purpose[:500], source[:200]),
            )
        return {
            "id": evidence_id, "trace_id": row["trace_id"], "created_at": row["created_at"], "expires_at": row["expires_at"],
            "categories": json.loads(row["categories_json"]), "locations": json.loads(row["locations_json"]),
            "destination": json.loads(row["destination_json"]), "payload": json.loads(plaintext),
        }

    def purge_expired_evidence(self) -> int:
        with self._connect() as connection:
            deleted = connection.execute("DELETE FROM encrypted_evidence WHERE expires_at<=?", (_now(),)).rowcount
            _audit(connection, "evidence.purged", "encrypted_evidence", None, {"deleted": deleted})
        return deleted

    def migrate_legacy_evidence(self) -> dict[str, int]:
        if self.evidence_key is None:
            raise RuntimeError("evidence encryption key is not configured")
        migrated = 0
        with self._connect() as connection:
            rows = connection.execute("SELECT id, request_body_json FROM traces WHERE request_body_json IS NOT NULL").fetchall()
        for row in rows:
            payload = json.loads(row["request_body_json"])
            findings = scan_payload(payload)
            if not findings:
                continue
            with self._connect() as connection:
                exists = connection.execute("SELECT 1 FROM encrypted_evidence WHERE trace_id=?", (row["id"],)).fetchone()
            if exists:
                continue
            evidence_id = self.store_evidence(row["id"], payload, findings, {"trust": "unknown", "name": "legacy"})
            if evidence_id:
                with self._connect() as connection:
                    connection.execute(
                        "UPDATE traces SET request_body_json=? WHERE id=?",
                        (json.dumps(redact_payload(payload, findings), ensure_ascii=False), row["id"]),
                    )
                migrated += 1
        return {"scanned": len(rows), "migrated": migrated}

    def sessions(
        self,
        limit: int = 100,
        protocol: str | None = None,
        model: str | None = None,
        risk: str | None = None,
        decision: str | None = None,
        capability: str | None = None,
        since: str | None = None,
        category: str | None = None,
    ) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM sessions ORDER BY last_seen_at DESC LIMIT 500").fetchall()
            result = [_json_row(row, ("protocols_json", "models_json", "authorization_json")) for row in rows]
            if capability:
                allowed_ids = {row[0] for row in connection.execute(
                    """SELECT DISTINCT t.session_record_id FROM traces t JOIN tool_actions a ON a.trace_id=t.id
                       WHERE a.capability=?""", (capability,)
                )}
                result = [row for row in result if row["id"] in allowed_ids]

            if result:
                session_ids = [row["id"] for row in result]
                placeholders = ", ".join("?" for _ in session_ids)
                dlp_info_rows = connection.execute(
                    f"""SELECT t.session_record_id, r.data_findings_json, r.policy_decision,
                               r.review_object, a.id AS alert_id, t.created_at, r.final_decision
                        FROM traces t
                        LEFT JOIN classification_runs r ON r.trace_id = t.id
                        LEFT JOIN alerts a ON a.trace_id = t.id
                        WHERE t.session_record_id IN ({placeholders})
                        ORDER BY t.created_at ASC""",
                    session_ids,
                ).fetchall()

                session_dlp_map: dict[str, dict[str, Any]] = {
                    sid: {
                        "findings_count": 0, "categories": set(), "has_dlp_alert": False,
                        "has_intent_alert": False, "dlp_alert_count": 0, "latest_trace_decision": "allow",
                    }
                    for sid in session_ids
                }
                for d_row in dlp_info_rows:
                    sid = d_row[0]
                    if not sid or sid not in session_dlp_map:
                        continue
                    findings_raw = d_row[1]
                    if findings_raw:
                        try:
                            findings = json.loads(findings_raw)
                            if isinstance(findings, list) and findings:
                                session_dlp_map[sid]["findings_count"] += len(findings)
                                for f in findings:
                                    cat = f.get("category")
                                    if cat:
                                        session_dlp_map[sid]["categories"].add(str(cat))
                        except Exception:
                            pass
                    review_object = d_row[3]
                    has_alert = bool(d_row[4])
                    final_decision = d_row[6] or d_row[2] or "allow"
                    session_dlp_map[sid]["latest_trace_decision"] = final_decision
                    if review_object == "outbound_request" and d_row[2] == "alert":
                        session_dlp_map[sid]["has_dlp_alert"] = True
                        session_dlp_map[sid]["dlp_alert_count"] += 1
                    elif has_alert:
                        session_dlp_map[sid]["has_intent_alert"] = True

                tool_risks = {sid: "low" for sid in session_ids}
                for action_row in connection.execute(
                    f"""SELECT t.session_record_id, a.risk FROM traces t
                        JOIN tool_actions a ON a.trace_id=t.id
                        WHERE t.session_record_id IN ({placeholders})""",
                    session_ids,
                ).fetchall():
                    sid, risk_value = action_row
                    if sid in tool_risks and risk_value in _RISK_ORDER:
                        if _RISK_ORDER.index(risk_value) > _RISK_ORDER.index(tool_risks[sid]):
                            tool_risks[sid] = risk_value

                for row in result:
                    sid = row["id"]
                    meta = session_dlp_map.get(sid, {})
                    row["dlp_findings_count"] = meta.get("findings_count", 0)
                    row["dlp_categories"] = sorted(meta.get("categories", set()))
                    row["has_dlp_alert"] = meta.get("has_dlp_alert", False)
                    row["dlp_alert_count"] = meta.get("dlp_alert_count", 0)
                    row["latest_trace_decision"] = meta.get("latest_trace_decision", "allow")
                    row["has_intent_alert"] = meta.get("has_intent_alert", False)
                    row["intent_risk"] = tool_risks.get(sid, "low")
                    row["risk_intent_summary"] = self.session_risk_summary(sid)

        if protocol:
            result = [row for row in result if protocol in row["protocols"]]
        if model:
            result = [row for row in result if model in row["models"]]
        if risk:
            result = [row for row in result if row["max_risk"] == risk]
        if decision == "allow":
            result = [row for row in result if row["allow_count"] > 0]
        elif decision == "alert":
            result = [row for row in result if row["alert_count"] > 0]
        if since:
            result = [row for row in result if row["last_seen_at"] >= since]
        if category == "dlp":
            result = [row for row in result if row.get("dlp_findings_count", 0) > 0 or row.get("has_dlp_alert")]
        elif category == "intent":
            result = [row for row in result if row.get("has_intent_alert") or (row.get("intent_risk") in {"medium", "high", "critical"})]
        return result[:min(max(limit, 1), 500)]

    def session(self, session_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
            if row is None:
                return None
            value = _json_row(row, ("protocols_json", "models_json", "authorization_json"))
            return self._enrich_session_dlp_facts(connection, value)

    def _enrich_session_dlp_facts(self, connection: sqlite3.Connection, session_data: dict[str, Any]) -> dict[str, Any]:
        sid = session_data["id"]
        dlp_info_rows = connection.execute(
            """SELECT t.id, t.created_at, r.data_findings_json, r.policy_decision,
                      r.review_object, (SELECT id FROM alerts a WHERE a.trace_id = t.id LIMIT 1) AS alert_id,
                      r.final_decision
               FROM traces t
               LEFT JOIN classification_runs r ON r.trace_id = t.id
               WHERE t.session_record_id = ?
               ORDER BY t.created_at ASC""",
            (sid,),
        ).fetchall()

        findings_count = 0
        categories: set[str] = set()
        has_dlp_alert = False
        dlp_alert_count = 0
        has_intent_alert = False
        latest_decision = "allow"

        for d_row in dlp_info_rows:
            findings_raw = d_row[2]
            decision = d_row[3]
            review_object = d_row[4]
            has_alert = bool(d_row[5])
            final_decision = d_row[6] or decision or "allow"
            latest_decision = final_decision

            if findings_raw:
                try:
                    findings = json.loads(findings_raw)
                    if isinstance(findings, list) and findings:
                        findings_count += len(findings)
                        for f in findings:
                            cat = f.get("category")
                            if cat:
                                categories.add(str(cat))
                except Exception:
                    pass
            if review_object == "outbound_request" and decision == "alert":
                has_dlp_alert = True
                dlp_alert_count += 1
            elif has_alert:
                has_intent_alert = True

        action_rows = connection.execute(
            """SELECT a.risk FROM traces t
               JOIN tool_actions a ON a.trace_id=t.id
               WHERE t.session_record_id = ?""",
            (sid,),
        ).fetchall()
        intent_risk = "low"
        for a_row in action_rows:
            risk_val = a_row[0]
            if risk_val in _RISK_ORDER and _RISK_ORDER.index(risk_val) > _RISK_ORDER.index(intent_risk):
                intent_risk = risk_val

        session_data["dlp_findings_count"] = findings_count
        session_data["dlp_categories"] = sorted(categories)
        session_data["has_dlp_alert"] = has_dlp_alert
        session_data["dlp_alert_count"] = dlp_alert_count
        session_data["latest_trace_decision"] = latest_decision
        session_data["has_intent_alert"] = has_intent_alert
        session_data["intent_risk"] = intent_risk
        session_data["risk_intent_summary"] = self.session_risk_summary(sid)
        return session_data

    def session_baseline_for_trace(self, trace_id: str) -> dict[str, Any] | None:
        """The session-wide authorization baseline accumulated for a trace's session."""
        with self._connect() as connection:
            row = connection.execute(
                """SELECT s.authorization_json FROM sessions s
                   JOIN traces t ON t.session_record_id=s.id WHERE t.id=?""",
                (trace_id,),
            ).fetchone()
        if row is None:
            return None
        value = json.loads(row[0] or "{}")
        return value if isinstance(value, dict) and value else None

    def backfill_sessions(self) -> dict[str, Any]:
        """Regroup historical traces into conversation sessions and rebuild the
        session-level read model (aggregates + authorization baselines).

        Uses the same resolution priority as the live path: explicit session id,
        then conversation fingerprint with prefix verification, then trace fallback.
        Per-trace classification records are preserved untouched; orphaned
        trace-fallback sessions created before session grouping existed are removed.
        Safe to re-run: resolution and aggregation are deterministic.
        """
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT id, created_at, protocol, model, session_id, session_record_id,
                          request_body_json
                   FROM traces ORDER BY created_at"""
            ).fetchall()
        sessions_before = len({row["session_record_id"] for row in rows})
        regrouped = 0
        with self._connect() as connection:
            for row in rows:
                payload = json.loads(row["request_body_json"]) if row["request_body_json"] else None
                messages = extract_messages(payload) if isinstance(payload, dict) else []
                fingerprint = fingerprint_messages(messages)
                resolved = _upsert_session(
                    connection,
                    external_session_id=row["session_id"],
                    conversation_fingerprint=fingerprint,
                    incoming_messages=messages,
                    fallback_id=f"trace:{row['id']}",
                    created_at=row["created_at"],
                    protocol=row["protocol"],
                    model=row["model"],
                    client_type="unknown",
                )
                if resolved != row["session_record_id"]:
                    regrouped += 1
                    connection.execute(
                        "UPDATE traces SET session_record_id=? WHERE id=?", (resolved, row["id"])
                    )
        baselines: dict[str, dict[str, Any]] = {}
        with self._connect() as connection:
            grouped = connection.execute(
                "SELECT session_record_id, request_body_json FROM traces ORDER BY created_at"
            ).fetchall()
        for row in grouped:
            payload = json.loads(row["request_body_json"]) if row["request_body_json"] else None
            if not isinstance(payload, dict):
                continue
            try:
                normalized = normalize(payload, source_format_override=None)
            except (ValueError, TypeError):
                continue
            user_messages = build_review_context(normalized).user_messages
            if not user_messages:
                continue
            current = baselines.get(row["session_record_id"]) or {"capabilities": [], "forbidden_capabilities": [], "statements": []}
            baselines[row["session_record_id"]] = _merge_authorization_values(current, authorization_signals(user_messages))
        with self._connect() as connection:
            for session_id, baseline in baselines.items():
                connection.execute(
                    "UPDATE sessions SET authorization_json=? WHERE id=?",
                    (json.dumps(baseline, ensure_ascii=False), session_id),
                )
            orphan_sessions_deleted = connection.execute(
                "DELETE FROM sessions WHERE id NOT IN (SELECT DISTINCT session_record_id FROM traces)"
            ).rowcount
            self._rebuild_session_aggregates(connection)
        return {
            "traces": len(rows),
            "sessions_before": sessions_before,
            "sessions_after": self._count_sessions_with_traces(),
            "regrouped_traces": regrouped,
            "baselines_written": len(baselines),
            "orphan_sessions_deleted": orphan_sessions_deleted,
        }

    def _rebuild_session_aggregates(self, connection: sqlite3.Connection) -> None:
        """Recompute every session's counters from its traces (after regrouping)."""
        rows = connection.execute(
            "SELECT session_record_id FROM traces GROUP BY session_record_id"
        ).fetchall()
        for row in rows:
            session_id = row[0]
            traces = connection.execute(
                "SELECT * FROM traces WHERE session_record_id=? ORDER BY created_at", (session_id,)
            ).fetchall()
            if not traces:
                continue
            trace_ids = [trace["id"] for trace in traces]
            protocols = list(dict.fromkeys(trace["protocol"] for trace in traces))
            models = list(dict.fromkeys(trace["model"] for trace in traces if trace["model"]))
            tool_call_count = 0
            if trace_ids:
                placeholders = ", ".join("?" for _ in trace_ids)
                tool_call_count = connection.execute(
                    f"SELECT COUNT(*) FROM tool_actions WHERE trace_id IN ({placeholders})", trace_ids
                ).fetchone()[0]
            allow_count = sum(1 for trace in traces if (trace["final_decision"] or trace["decision"]) == "allow")
            alert_count = sum(1 for trace in traces if (trace["final_decision"] or trace["decision"]) == "alert")
            max_risk = "low"
            for trace in traces:
                risk = trace["risk"]
                if risk in _RISK_ORDER and _RISK_ORDER.index(risk) > _RISK_ORDER.index(max_risk):
                    max_risk = risk
            connection.execute(
                """UPDATE sessions SET created_at=?, last_seen_at=?, protocols_json=?, models_json=?,
                   call_count=?, tool_call_count=?, allow_count=?, alert_count=?, max_risk=? WHERE id=?""",
                (
                    traces[0]["created_at"], traces[-1]["created_at"],
                    json.dumps(protocols), json.dumps(models),
                    len(traces), tool_call_count, allow_count, alert_count, max_risk, session_id,
                ),
            )

    def _count_sessions_with_traces(self) -> int:
        with self._connect() as connection:
            return connection.execute(
                "SELECT COUNT(*) FROM sessions WHERE id IN (SELECT DISTINCT session_record_id FROM traces)"
            ).fetchone()[0]

    def timeline(self, session_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            traces = connection.execute("SELECT * FROM traces WHERE session_record_id=? ORDER BY created_at", (session_id,)).fetchall()
            result: list[dict[str, Any]] = []
            for trace in traces:
                result.append({"type": "user_message", "at": trace["created_at"], "trace_id": trace["id"], "text": trace["latest_user_text"], "session_evidence": json.loads(trace["session_evidence_json"] or "{}")})
                result.append({"type": "model_call", "at": trace["created_at"], "trace_id": trace["id"], "model": trace["model"], "protocol": trace["protocol"], "request_body": json.loads(trace["request_body_json"] or "null"), "response_body": json.loads(trace["response_body_json"] or "null"), "response_content_type": trace["response_content_type"], "response_capture_complete": bool(trace["response_capture_complete"])})
                actions = connection.execute("SELECT * FROM tool_actions WHERE trace_id=? ORDER BY created_at", (trace["id"],)).fetchall()
                result.extend({"type": "tool_action", "at": row["created_at"], "trace_id": trace["id"], "tool_name": row["tool_name"], "capability": row["capability"], "target": row["target"]} for row in actions)
                run = connection.execute("SELECT * FROM classification_runs WHERE trace_id=? ORDER BY completed_at DESC LIMIT 1", (trace["id"],)).fetchone()
                if run:
                    stages = connection.execute("SELECT * FROM classification_stages WHERE run_id=? ORDER BY rowid", (run["id"],)).fetchall()
                    result.extend({"type": "classification_stage", "at": run["completed_at"], "trace_id": trace["id"], "stage": row["stage"], "status": row["status"], "verdict": row["verdict"], "reason_code": row["reason_code"], "reason": row["reason"], "model": row["model"], "latency_ms": row["latency_ms"], "risk": row["risk"], "matched_rules": json.loads(row["matched_rule_versions_json"] or "[]"), "evidence": json.loads(row["evidence_json"] or "[]")} for row in stages)
                    result.append({"type": "final_decision", "at": run["completed_at"], "trace_id": trace["id"], "decision": run["final_decision"], "stage": run["final_stage"]})
            risk_rows = connection.execute("SELECT * FROM session_risk_segments WHERE session_id=? ORDER BY started_at", (session_id,)).fetchall()
            result.extend({"type": "session_risk", "at": row["started_at"], "ended_at": row["ended_at"], "trace_id": row["trace_id"], "purpose_risk": row["purpose_risk"], "transfer_intent": row["transfer_intent"], "severity": row["severity"], "state": row["state"], "reason_code": row["reason_code"], "summary": row["summary"]} for row in risk_rows)
        return sorted(result, key=lambda item: str(item["at"]))

    def session_detail(self, session_id: str) -> dict[str, Any] | None:
        """Return a session plus every trace's full audit payload in one call.

        This is the read-model for the console's audit timeline: session
        metadata, per-trace raw request/response, proposed tool actions, the
        complete classification report (review transcript, stages, alignment),
        and any alerts raised for that trace.
        """
        session = self.session(session_id)
        if session is None:
            return None
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM traces WHERE session_record_id=? ORDER BY created_at", (session_id,)
            ).fetchall()
        trace_ids = [row["id"] for row in rows]
        actions_by_trace: dict[str, list[dict[str, Any]]] = {tid: [] for tid in trace_ids}
        alerts_by_trace: dict[str, list[dict[str, Any]]] = {tid: [] for tid in trace_ids}
        if trace_ids:
            placeholders = ", ".join("?" for _ in trace_ids)
            with self._connect() as connection:
                for action in connection.execute(
                    f"SELECT * FROM tool_actions WHERE trace_id IN ({placeholders}) ORDER BY created_at",
                    trace_ids,
                ).fetchall():
                    actions_by_trace[action["trace_id"]].append(_tool_action_row(action))
                for alert in connection.execute(
                    f"SELECT * FROM alerts WHERE trace_id IN ({placeholders}) ORDER BY created_at",
                    trace_ids,
                ).fetchall():
                    alerts_by_trace[alert["trace_id"]].append(_alert_row(alert))
        traces: list[dict[str, Any]] = []
        for row in rows:
            trace_id = row["id"]
            traces.append({
                "trace_id": trace_id,
                "created_at": row["created_at"],
                "model": row["model"],
                "protocol": row["protocol"],
                "method": row["method"],
                "path": row["path"],
                "latest_user_text": row["latest_user_text"],
                "response_status": row["response_status"],
                "latency_ms": row["latency_ms"],
                "response_capture_complete": bool(row["response_capture_complete"]),
                "session_evidence": json.loads(row["session_evidence_json"] or "{}"),
                "request_body": json.loads(row["request_body_json"]) if row["request_body_json"] else None,
                "response_body": json.loads(row["response_body_json"]) if row["response_body_json"] else None,
                "tool_actions": actions_by_trace.get(trace_id, []),
                "classification": self.classification(trace_id),
                "alerts": alerts_by_trace.get(trace_id, []),
            })
        return {"session": session, "traces": traces, "risk_intent_segments": self.session_risk_segments(session_id)}

    def classification(self, trace_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            run = connection.execute("SELECT * FROM classification_runs WHERE trace_id=? ORDER BY completed_at DESC LIMIT 1", (trace_id,)).fetchone()
            if run is None:
                trace = connection.execute("SELECT * FROM traces WHERE id=?", (trace_id,)).fetchone()
                if trace is None:
                    return None
                return {
                    "trace_id": trace_id, "legacy": True,
                    "final_decision": trace["final_decision"] or trace["decision"] or "unknown",
                    "final_stage": trace["final_stage"], "reason_code": trace["final_reason_code"],
                    "reason": trace["final_reason"] or "旧记录无数据", "review_transcript": [],
                    "stages": [{"stage": stage, "status": "skipped", "verdict": "旧记录无数据", "reason_code": "LEGACY_NO_STAGE_DATA", "reason": "旧记录无数据", "evidence": []} for stage in ("rules", "fast_llm", "deep_llm")],
                }
            stages = connection.execute("SELECT * FROM classification_stages WHERE run_id=? ORDER BY rowid", (run["id"],)).fetchall()
        result = _json_row(run, (
            "review_transcript_json", "data_findings_json", "destination_json",
            "matched_policies_json", "identity_json",
        ))
        result["stages"] = [_json_row(row, ("matched_rule_ids_json", "matched_rule_versions_json", "evidence_json")) for row in stages]
        return result

    def alerts(
        self,
        limit: int = 100,
        status: str | None = None,
        alert_type: str | None = None,
        hit_source: str | None = None,
        review_status: str | None = None,
        divergence: bool | None = None,
        channel_source: str | None = None,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM alerts"
        conditions = []
        params: list[Any] = []
        if status:
            conditions.append("status=?")
            params.append(status)
        if channel_source:
            if channel_source in ("rule", "rule_only"):
                conditions.append("(channel_source='rule' OR hit_source='rule_only')")
            elif channel_source in ("llm", "llm_only"):
                conditions.append("(channel_source='llm' OR hit_source='llm_only')")
            elif channel_source in ("dual", "both"):
                conditions.append("(channel_source='dual' OR hit_source='dual')")
            else:
                conditions.append("channel_source=?")
                params.append(channel_source)
        if hit_source:
            if hit_source == "rule_hit":
                conditions.append("(hit_source IN ('rule_only', 'dual') OR channel_source IN ('rule', 'dual') OR rule_severity IS NOT NULL)")
            elif hit_source == "llm_hit":
                conditions.append("(hit_source IN ('llm_only', 'dual') OR channel_source IN ('llm', 'dual') OR llm_severity IS NOT NULL)")
            elif hit_source == "rule_only":
                conditions.append("(hit_source='rule_only' OR channel_source='rule')")
            elif hit_source == "llm_only":
                conditions.append("(hit_source='llm_only' OR channel_source='llm')")
            elif hit_source in ("dual", "both"):
                conditions.append("(hit_source='dual' OR channel_source='dual')")
            else:
                conditions.append("(hit_source=? OR channel_source=?)")
                params.extend([hit_source, hit_source])
        if review_status:
            conditions.append("review_status=?")
            params.append(review_status)
        if divergence is not None:
            conditions.append("divergence=?")
            params.append(1 if divergence else 0)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(min(limit, 500))
        with self._connect() as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        result = [_alert_row(row) for row in rows]
        if alert_type:
            result = [row for row in result if row.get("alert_type") == alert_type]
        return result

    def alert(self, alert_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        return _alert_row(row) if row else None

    def update_alert(self, alert_id: str, *, status: str, note: str = "", feedback: str | None = None) -> dict[str, Any]:
        if status not in {"open", "acknowledged", "false_positive", "resolved"}:
            raise ValueError("invalid alert status")
        acknowledged = _now() if status != "open" else None
        with self._connect() as connection:
            connection.execute("UPDATE alerts SET status=?, operator_note=?, acknowledged_at=?, feedback=COALESCE(?, feedback) WHERE id=?", (status, note[:4000], acknowledged, feedback, alert_id))
            if connection.total_changes == 0:
                raise KeyError("alert not found")
            _audit(connection, "alert.updated", "alert", alert_id, {"status": status})
        value = self.alert(alert_id)
        assert value is not None
        return value

    def dashboard(self) -> dict[str, Any]:
        with self._connect() as connection:
            trace_count = connection.execute("SELECT COUNT(*) FROM traces").fetchone()[0]
            session_count = connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
            alert_count = connection.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]
            stages = {row[0]: row[1] for row in connection.execute("SELECT stage, COUNT(*) FROM classification_stages GROUP BY stage")}
            decisions = {row[0] or "pending": row[1] for row in connection.execute("SELECT final_decision, COUNT(*) FROM traces GROUP BY final_decision")}
            reasons = [{"reason_code": row[0], "count": row[1]} for row in connection.execute("SELECT reason_code, COUNT(*) c FROM alerts GROUP BY reason_code ORDER BY c DESC LIMIT 8")]
            latencies = [float(row[0]) for row in connection.execute("SELECT total_latency_ms FROM classification_runs ORDER BY total_latency_ms")]
            latest_status = connection.execute("SELECT response_status FROM traces WHERE response_status IS NOT NULL ORDER BY created_at DESC LIMIT 1").fetchone()
            dlp_rows = connection.execute(
                "SELECT data_findings_json, destination_json, policy_decision FROM classification_runs WHERE review_object='outbound_request'"
            ).fetchall()
        category_counts: dict[str, int] = {}
        destination_counts: dict[str, int] = {}
        dlp_alerts = 0
        for row in dlp_rows:
            for finding in json.loads(row["data_findings_json"] or "[]"):
                category = str(finding.get("category", "unknown"))
                category_counts[category] = category_counts.get(category, 0) + 1
            destination = json.loads(row["destination_json"] or "{}")
            target = str(destination.get("name") or destination.get("model") or "unregistered")
            destination_counts[target] = destination_counts.get(target, 0) + 1
            dlp_alerts += int(row["policy_decision"] == "alert")
        return {
            "trace_count": trace_count, "session_count": session_count, "open_alert_count": alert_count,
            "alert_rate": (decisions.get("alert", 0) / trace_count if trace_count else 0),
            "stage_counts": stages, "decisions": decisions, "top_reasons": reasons,
            "classification_latency_ms": {"p50": _percentile(latencies, 0.50), "p95": _percentile(latencies, 0.95)},
            "dlp": {
                "reviewed": len(dlp_rows), "alerts": dlp_alerts,
                "category_counts": category_counts, "destination_counts": destination_counts,
            },
            "health": {
                "gateway": "healthy",
                "upstream": "healthy" if latest_status and latest_status[0] < 500 else "unknown",
                "fast": "configured" if os.getenv("AUTOMODE_FAST_URL") and os.getenv("AUTOMODE_FAST_MODEL") else "not_configured",
                "deep": "configured" if os.getenv("AUTOMODE_DEEP_URL") and os.getenv("AUTOMODE_DEEP_MODEL") else "not_configured",
            },
        }

    def settings(self) -> dict[str, Any]:
        result = {
            "operating_mode": "observe", "retention_days": 30, "store_raw": self.store_raw,
            "evidence_encryption_configured": self.evidence_key is not None,
            "trusted_proxy_cidrs_configured": bool(os.getenv("AUTOMODE_TRUSTED_PROXY_CIDRS")),
        }
        with self._connect() as connection:
            for row in connection.execute("SELECT key, value_json FROM settings"):
                if "key" not in row["key"].lower() and "token" not in row["key"].lower():
                    result[row["key"]] = json.loads(row["value_json"])
        for stage in ("FAST", "DEEP"):
            key = os.getenv(f"AUTOMODE_{stage}_API_KEY") or os.getenv("AUTOMODE_REVIEWER_API_KEY")
            result[f"{stage.lower()}_api_key_configured"] = bool(key)
            result[f"{stage.lower()}_api_key_masked"] = f"••••{key[-4:]}" if key else None
            result[f"{stage.lower()}_model"] = os.getenv(f"AUTOMODE_{stage}_MODEL") or os.getenv("AUTOMODE_REVIEWER_MODEL")
            result[f"{stage.lower()}_url"] = os.getenv(f"AUTOMODE_{stage}_URL") or os.getenv("AUTOMODE_REVIEWER_URL")
        return result

    def update_settings(self, values: dict[str, Any]) -> dict[str, Any]:
        secret_keys = {"fast_api_key", "deep_api_key"}
        runtime_keys = {"fast_url", "fast_model", "deep_url", "deep_model"}
        allowed = {"operating_mode", "retention_days", "store_raw", *secret_keys, *runtime_keys}
        unknown = set(values) - allowed
        if unknown:
            raise ValueError(f"unsupported settings: {', '.join(sorted(unknown))}")
        for key in ("fast_model", "deep_model"):
            if key in values:
                model = str(values[key])
                if model != model.strip() or model.endswith(("\"", "'", "”", "’", "」")):
                    raise ValueError(f"{key} contains trailing whitespace or quote; remove it and retry")
        with self._connect() as connection:
            for key, value in values.items():
                if key in secret_keys:
                    os.environ[f"AUTOMODE_{key.upper()}"] = str(value)
                    continue
                if key in runtime_keys:
                    os.environ[f"AUTOMODE_{key.upper()}"] = str(value)
                connection.execute("INSERT INTO settings VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at", (key, json.dumps(value), _now()))
            _audit(connection, "settings.updated", "settings", None, {"keys": sorted(values), "secret_values_stored": False})
        return self.settings()

    # Prompts management --------------------------------------------------------
    def get_prompts(self) -> dict[str, str]:
        with self._connect() as connection:
            row = connection.execute("SELECT value_json FROM settings WHERE key='prompts'").fetchone()
        custom = json.loads(row[0]) if row and row[0] else {}
        return {**DEFAULT_PROMPTS, **custom}

    def get_default_prompts(self) -> dict[str, str]:
        return dict(DEFAULT_PROMPTS)

    def set_prompt(self, name: str, content: str) -> dict[str, str]:
        if name not in DEFAULT_PROMPTS:
            raise ValueError(f"unknown prompt name: {name}")
        with self._connect() as connection:
            row = connection.execute("SELECT value_json FROM settings WHERE key='prompts'").fetchone()
            current = json.loads(row[0]) if row and row[0] else {}
            current[name] = content
            connection.execute(
                "INSERT INTO settings (key, value_json, updated_at) VALUES ('prompts', ?, ?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at",
                (json.dumps(current, ensure_ascii=False), _now()),
            )
            _audit(connection, "prompt.updated", "prompt", name, {"length": len(content)})
        return self.get_prompts()

    def update_prompts(self, prompts: dict[str, str]) -> dict[str, str]:
        for name in prompts:
            if name not in DEFAULT_PROMPTS:
                raise ValueError(f"unknown prompt name: {name}")
        with self._connect() as connection:
            row = connection.execute("SELECT value_json FROM settings WHERE key='prompts'").fetchone()
            current = json.loads(row[0]) if row and row[0] else {}
            current.update(prompts)
            connection.execute(
                "INSERT INTO settings (key, value_json, updated_at) VALUES ('prompts', ?, ?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at",
                (json.dumps(current, ensure_ascii=False), _now()),
            )
            _audit(connection, "prompts.updated", "prompt", "all", {"keys": list(prompts.keys())})
        return self.get_prompts()

    def reset_prompts(self, name: str | None = None) -> dict[str, str]:
        with self._connect() as connection:
            if name is None:
                connection.execute("DELETE FROM settings WHERE key='prompts'")
                _audit(connection, "prompts.reset", "prompt", "all", {})
            else:
                if name not in DEFAULT_PROMPTS:
                    raise ValueError(f"unknown prompt name: {name}")
                row = connection.execute("SELECT value_json FROM settings WHERE key='prompts'").fetchone()
                if row and row[0]:
                    current = json.loads(row[0])
                    current.pop(name, None)
                    connection.execute(
                        "INSERT INTO settings (key, value_json, updated_at) VALUES ('prompts', ?, ?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at",
                        (json.dumps(current, ensure_ascii=False), _now()),
                    )
                _audit(connection, "prompt.reset", "prompt", name, {})
        return self.get_prompts()

    # Detectors management ------------------------------------------------------
    def get_disabled_detectors(self) -> set[str]:
        with self._connect() as connection:
            row = connection.execute("SELECT value_json FROM settings WHERE key='disabled_detectors'").fetchone()
        return set(json.loads(row[0])) if row and row[0] else set()

    def get_custom_detectors(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            row = connection.execute("SELECT value_json FROM settings WHERE key='custom_detectors'").fetchone()
        return list(json.loads(row[0])) if row and row[0] else []

    def add_custom_detector(self, name: str, category: str, description: str, pattern: str) -> dict[str, Any]:
        # Validate regex pattern
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"正则表达式格式错误: {exc}") from exc

        category_allowed = {"credential", "pii", "source_code", "admin_keyword"}
        if category not in category_allowed:
            raise ValueError(f"无效的检测类别: {category}")

        det_id = f"cust_{uuid.uuid4().hex[:8]}"
        new_item = {
            "id": det_id,
            "name": name.strip() or "自定义检测器",
            "category": category,
            "description": description.strip(),
            "pattern": pattern.strip(),
            "custom": True,
        }

        with self._connect() as connection:
            current = self.get_custom_detectors()
            current.append(new_item)
            connection.execute(
                "INSERT INTO settings (key, value_json, updated_at) VALUES ('custom_detectors', ?, ?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at",
                (json.dumps(current, ensure_ascii=False), _now()),
            )
            _audit(connection, "detector.created", "detector", det_id, {"name": name, "category": category})

        detectors = {d["id"]: d for d in self.get_detectors()}
        return detectors[det_id]

    def delete_custom_detector(self, detector_id: str) -> bool:
        with self._connect() as connection:
            current = self.get_custom_detectors()
            filtered = [d for d in current if d["id"] != detector_id]
            if len(filtered) == len(current):
                raise KeyError(f"自定义检测器不存在: {detector_id}")
            connection.execute(
                "INSERT INTO settings (key, value_json, updated_at) VALUES ('custom_detectors', ?, ?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at",
                (json.dumps(filtered, ensure_ascii=False), _now()),
            )
            # Also remove from disabled list if it was disabled
            disabled = self.get_disabled_detectors()
            if detector_id in disabled:
                disabled.discard(detector_id)
                connection.execute(
                    "INSERT INTO settings (key, value_json, updated_at) VALUES ('disabled_detectors', ?, ?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at",
                    (json.dumps(sorted(disabled), ensure_ascii=False), _now()),
                )
            _audit(connection, "detector.deleted", "detector", detector_id, {})
        return True

    def get_detectors(self) -> list[dict[str, Any]]:
        disabled = self.get_disabled_detectors()
        builtin = [
            {
                "id": item["id"],
                "name": item["name"],
                "category": item["category"],
                "description": item["description"],
                "pattern": item["pattern"],
                "enabled": item["id"] not in disabled,
                "custom": False,
            }
            for item in BUILTIN_DETECTORS
        ]
        custom = [
            {
                "id": item["id"],
                "name": item["name"],
                "category": item["category"],
                "description": item["description"],
                "pattern": item["pattern"],
                "enabled": item["id"] not in disabled,
                "custom": True,
            }
            for item in self.get_custom_detectors()
        ]
        return builtin + custom

    def set_detector_enabled(self, detector_id: str, enabled: bool) -> dict[str, Any]:
        all_detectors = self.get_detectors()
        if not any(item["id"] == detector_id for item in all_detectors):
            raise KeyError(f"detector not found: {detector_id}")
        with self._connect() as connection:
            disabled = self.get_disabled_detectors()
            if enabled:
                disabled.discard(detector_id)
            else:
                disabled.add(detector_id)
            connection.execute(
                "INSERT INTO settings (key, value_json, updated_at) VALUES ('disabled_detectors', ?, ?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at",
                (json.dumps(sorted(disabled), ensure_ascii=False), _now()),
            )
            _audit(connection, "detector.enabled" if enabled else "detector.disabled", "detector", detector_id, {})
        detectors = {d["id"]: d for d in self.get_detectors()}
        return detectors[detector_id]

    # Controlled Tool Schemas management -----------------------------------------
    def get_tool_schemas(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            row = connection.execute("SELECT value_json FROM settings WHERE key='tool_schemas'").fetchone()
        schemas = list(json.loads(row[0])) if row and row[0] else []
        return schemas

    def add_tool_schema(
        self,
        tool_name: str,
        content_fingerprint: str,
        *,
        agent_id: str = "claude_code",
        schema_version: str = "v1.0",
        description_snippet: str = "",
        reason: str = "内置受控工具",
    ) -> dict[str, Any]:
        tool_name = tool_name.strip()
        content_fingerprint = content_fingerprint.strip().lower()
        if not tool_name or not content_fingerprint:
            raise ValueError("tool_name and content_fingerprint are required")
        if len(content_fingerprint) != 64:
            raise ValueError("content_fingerprint must be a 64-character SHA-256 hash")

        schema_id = f"schema_{uuid.uuid4().hex[:8]}"
        new_item = {
            "id": schema_id,
            "agent_id": agent_id.strip() or "claude_code",
            "tool_name": tool_name,
            "schema_version": schema_version.strip() or "v1.0",
            "content_fingerprint": content_fingerprint,
            "description_snippet": description_snippet.strip()[:100],
            "reason": reason.strip() or "内置受控工具",
            "enabled": True,
            "created_at": _now(),
        }

        with self._connect() as connection:
            current = self.get_tool_schemas()
            for item in current:
                if item.get("tool_name") == tool_name and item.get("content_fingerprint") == content_fingerprint:
                    item["enabled"] = True
                    if reason:
                        item["reason"] = reason
                    connection.execute(
                        "INSERT INTO settings (key, value_json, updated_at) VALUES ('tool_schemas', ?, ?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at",
                        (json.dumps(current, ensure_ascii=False), _now()),
                    )
                    return item
            current.append(new_item)
            connection.execute(
                "INSERT INTO settings (key, value_json, updated_at) VALUES ('tool_schemas', ?, ?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at",
                (json.dumps(current, ensure_ascii=False), _now()),
            )
            _audit(connection, "tool_schema.created", "tool_schema", schema_id, {"tool_name": tool_name, "fingerprint": content_fingerprint})
        return new_item

    def set_tool_schema_enabled(self, schema_id: str, enabled: bool) -> dict[str, Any]:
        with self._connect() as connection:
            current = self.get_tool_schemas()
            target = next((item for item in current if item["id"] == schema_id), None)
            if target is None:
                raise KeyError(f"tool schema not found: {schema_id}")
            target["enabled"] = bool(enabled)
            connection.execute(
                "INSERT INTO settings (key, value_json, updated_at) VALUES ('tool_schemas', ?, ?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at",
                (json.dumps(current, ensure_ascii=False), _now()),
            )
            _audit(connection, "tool_schema.enabled" if enabled else "tool_schema.disabled", "tool_schema", schema_id, {})
        return target

    def delete_tool_schema(self, schema_id: str) -> bool:
        with self._connect() as connection:
            current = self.get_tool_schemas()
            filtered = [item for item in current if item["id"] != schema_id]
            if len(filtered) == len(current):
                raise KeyError(f"tool schema not found: {schema_id}")
            connection.execute(
                "INSERT INTO settings (key, value_json, updated_at) VALUES ('tool_schemas', ?, ?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at",
                (json.dumps(filtered, ensure_ascii=False), _now()),
            )
            _audit(connection, "tool_schema.deleted", "tool_schema", schema_id, {})
        return True

    def record_test_run(
        self,
        input_value: dict[str, Any],
        temporary_rule: dict[str, Any] | None,
        result: dict[str, Any],
    ) -> str:
        run_id = str(uuid.uuid4())
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO test_runs VALUES (?, ?, ?, ?, ?)",
                (
                    run_id, _now(), json.dumps(_sanitize_payload(input_value), ensure_ascii=False),
                    json.dumps(temporary_rule, ensure_ascii=False) if temporary_rule else None,
                    json.dumps(_sanitize_payload(_without_reasoning(result)), ensure_ascii=False),
                ),
            )
        return run_id

    def list(self, limit: int = 50, session_id: str | None = None) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 500))
        with self._connect() as connection:
            if session_id:
                rows = connection.execute(
                    """SELECT * FROM traces WHERE session_id=? ORDER BY created_at DESC LIMIT ?""",
                    (session_id, limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM traces ORDER BY created_at DESC LIMIT ?", (limit,)
                ).fetchall()
        return [_public_row(row) for row in rows]

    def get(self, trace_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM traces WHERE id=?", (trace_id,)).fetchone()
        return _public_row(row, include_raw=True) if row else None

    # Source management --------------------------------------------------------

    def create_source(
        self,
        id: str,
        name: str,
        token: str,
        *,
        allow_trusted_identity: bool = False,
        rate_limit_per_minute: int | None = None,
        enabled: bool = True,
    ) -> dict[str, Any]:
        now = _now()
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO sources (id, name, token, allow_trusted_identity, rate_limit_per_minute, enabled, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (id, name, token, int(allow_trusted_identity), rate_limit_per_minute, int(enabled), now, now),
            )
        return self.get_source(id)  # type: ignore[return-value]

    def get_source(self, source_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM sources WHERE id=?", (source_id,)).fetchone()
        if not row:
            return None
        res = dict(row)
        res["allow_trusted_identity"] = bool(res["allow_trusted_identity"])
        res["enabled"] = bool(res["enabled"])
        return res

    def get_source_by_token(self, token: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM sources WHERE token=?", (token,)).fetchone()
        if not row:
            return None
        res = dict(row)
        res["allow_trusted_identity"] = bool(res["allow_trusted_identity"])
        res["enabled"] = bool(res["enabled"])
        return res

    def list_sources(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM sources ORDER BY created_at ASC").fetchall()
        result = []
        for row in rows:
            res = dict(row)
            res["allow_trusted_identity"] = bool(res["allow_trusted_identity"])
            res["enabled"] = bool(res["enabled"])
            result.append(res)
        return result

    def update_source(self, source_id: str, **kwargs: Any) -> dict[str, Any] | None:
        if not kwargs:
            return self.get_source(source_id)
        fields = []
        values: list[Any] = []
        for k, v in kwargs.items():
            if k in {"name", "token", "rate_limit_per_minute"}:
                fields.append(f"{k}=?")
                values.append(v)
            elif k in {"allow_trusted_identity", "enabled"}:
                fields.append(f"{k}=?")
                values.append(int(bool(v)))
        fields.append("updated_at=?")
        values.append(_now())
        values.append(source_id)
        with self._connect() as connection:
            connection.execute(f"UPDATE sources SET {', '.join(fields)} WHERE id=?", values)
        return self.get_source(source_id)

    def delete_source(self, source_id: str) -> bool:
        with self._connect() as connection:
            connection.execute("DELETE FROM sources WHERE id=?", (source_id,))
            return connection.total_changes > 0

    # Event ingestion & pipeline management ------------------------------------

    def resolve_event_id(self, event_id: str, source_id: str | None = None) -> str | None:
        """Resolve an internal event UUID, accepting the legacy external ID alias.

        A source is required when an external ID is shared by more than one
        source. This keeps old management/test callers working without allowing
        a cross-source lookup to select an arbitrary event.
        """
        with self._connect() as connection:
            row = connection.execute("SELECT id FROM events WHERE id=?", (event_id,)).fetchone()
            if row is not None:
                return str(row["id"])
            if source_id:
                row = connection.execute(
                    "SELECT id FROM events WHERE source_id=? AND external_event_id=?",
                    (source_id, event_id),
                ).fetchone()
            else:
                rows = connection.execute(
                    "SELECT id FROM events WHERE external_event_id=? LIMIT 2", (event_id,)
                ).fetchall()
                row = rows[0] if len(rows) == 1 else None
            return str(row["id"]) if row is not None else None

    def reserve_event(
        self,
        *,
        internal_id: str | None = None,
        external_event_id: str,
        source_id: str,
        call_id: str,
        attempt_id: str | None = None,
        event_type: str,
        protocol: str,
        capture_stage: str,
        content_integrity: str,
        is_realtime: bool = True,
        timestamp: str,
        payload_hash: str,
        body_hash: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Atomically reserve a source/external ID before writing its body.

        The reservation deliberately has no event task. A task is created only
        by :meth:`finalize_event_storage`, after the encrypted file is durable.
        """
        received_at = _now()
        internal_id = internal_id or str(uuid.uuid4())
        metadata_json = json.dumps(_sanitize_event_metadata(metadata or {}), ensure_ascii=False)
        with self._connect() as connection:
            try:
                connection.execute(
                    """INSERT INTO events (
                        id, external_event_id, source_id, call_id, attempt_id, event_type, protocol,
                        capture_stage, content_integrity, is_realtime, timestamp, received_at,
                        payload_hash, body_hash, processing_status, association_status, rule_status,
                        llm_status, retry_count, metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'persisting', 'none', 'pending', 'pending', 0, ?)""",
                    (
                        internal_id, external_event_id, source_id, call_id, attempt_id, event_type,
                        protocol, capture_stage, content_integrity, int(is_realtime), timestamp,
                        received_at, payload_hash, body_hash, metadata_json,
                    ),
                )
            except sqlite3.IntegrityError:
                row = connection.execute(
                    "SELECT * FROM events WHERE source_id=? AND external_event_id=?",
                    (source_id, external_event_id),
                ).fetchone()
                if row is None:
                    raise
                existing = dict(row)
                if existing["payload_hash"] != payload_hash:
                    return {"status": "conflict", "event": existing}
                return {
                    "status": "duplicate" if existing.get("disk_buffer_path") else "pending",
                    "event": existing,
                }
        return {"status": "reserved", "internal_id": internal_id}

    def finalize_event_storage(self, internal_id: str, disk_buffer_path: str) -> dict[str, Any]:
        """Publish a durable body into the task index exactly once."""
        now = _now()
        with self._connect() as connection:
            connection.execute(
                """UPDATE events SET disk_buffer_path=?, processing_status='pending'
                   WHERE id=? AND processing_status='persisting'""",
                (disk_buffer_path, internal_id),
            )
            row = connection.execute("SELECT * FROM events WHERE id=?", (internal_id,)).fetchone()
            if row is None:
                raise KeyError(f"event not found: {internal_id}")
            if not row["disk_buffer_path"]:
                raise RuntimeError(f"event storage is not finalized: {internal_id}")
            task = connection.execute(
                "SELECT id FROM event_tasks WHERE event_id=? AND stage='rule' LIMIT 1", (internal_id,)
            ).fetchone()
            if task is None:
                connection.execute(
                    """INSERT INTO event_tasks (id, event_id, stage, status, retry_count, created_at, updated_at)
                       VALUES (?, ?, 'rule', 'pending', 0, ?, ?)""",
                    (str(uuid.uuid4()), internal_id, now, now),
                )
        return dict(row)

    def remove_event_reservation(self, internal_id: str) -> bool:
        """Remove a reservation that never reached durable storage."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT processing_status, disk_buffer_path FROM events WHERE id=?", (internal_id,)
            ).fetchone()
            if row is None or row["processing_status"] != "persisting" or row["disk_buffer_path"]:
                return False
            connection.execute("DELETE FROM event_tasks WHERE event_id=?", (internal_id,))
            connection.execute("DELETE FROM events WHERE id=?", (internal_id,))
            return connection.total_changes > 0

    def list_persisting_events(self) -> list[dict[str, Any]]:
        """Return reservations awaiting file finalization for startup recovery."""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM events WHERE processing_status='persisting' ORDER BY received_at ASC"
            ).fetchall()
        return [dict(row) for row in rows]

    def record_event(
        self,
        *,
        event_id: str,
        source_id: str,
        call_id: str,
        attempt_id: str | None = None,
        event_type: str,
        protocol: str,
        capture_stage: str,
        content_integrity: str,
        is_realtime: bool = True,
        timestamp: str,
        payload_hash: str,
        body_hash: str | None = None,
        disk_buffer_path: str | None = None,
        metadata: dict[str, Any] | None = None,
        internal_id: str | None = None,
    ) -> dict[str, Any]:
        # This compatibility wrapper keeps the old direct ingestion API while
        # routing all new records through the reservation/finalization protocol.
        result = self.reserve_event(
            internal_id=internal_id,
            external_event_id=event_id, source_id=source_id, call_id=call_id,
            attempt_id=attempt_id, event_type=event_type, protocol=protocol,
            capture_stage=capture_stage, content_integrity=content_integrity,
            is_realtime=is_realtime, timestamp=timestamp, payload_hash=payload_hash,
            body_hash=body_hash,
            metadata=metadata,
        )
        if result["status"] == "conflict":
            raise ValueError(f"event_id '{event_id}' already exists with different content")
        if result["status"] == "reserved":
            resolved = result["internal_id"]
            if disk_buffer_path:
                self.finalize_event_storage(resolved, disk_buffer_path)
            return self.get_event(resolved)  # type: ignore[return-value]
        return result["event"]

    def get_event(self, event_id: str, source_id: str | None = None) -> dict[str, Any] | None:
        internal_id = self.resolve_event_id(event_id, source_id=source_id)
        if internal_id is None:
            return None
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM events WHERE id=?", (internal_id,)).fetchone()
        return dict(row) if row else None

    def get_event_by_source_and_id(self, source_id: str, event_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM events WHERE source_id=? AND external_event_id=?",
                (source_id, event_id),
            ).fetchone()
        return dict(row) if row else None

    def find_correlated_events(
        self,
        source_id: str,
        call_id: str,
        attempt_id: str | None = None,
        event_type: str | None = None,
        capture_stage: str | None = None,
        is_realtime: bool | None = None,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM events WHERE source_id=? AND call_id=?"
        params: list[Any] = [source_id, call_id]
        if attempt_id is not None:
            query += " AND attempt_id=?"
            params.append(attempt_id)
        else:
            query += " AND (attempt_id IS NULL OR attempt_id='')"
        if event_type is not None:
            query += " AND event_type=?"
            params.append(event_type)
        if capture_stage is not None:
            query += " AND capture_stage=?"
            params.append(capture_stage)
        if is_realtime is not None:
            query += " AND is_realtime=?"
            params.append(int(is_realtime))
        query += " ORDER BY received_at ASC"
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def update_event_status(
        self,
        event_id: str,
        *,
        processing_status: str | None = None,
        association_status: str | None = None,
        rule_status: str | None = None,
        llm_status: str | None = None,
        rule_verdict: dict[str, Any] | None = None,
        llm_verdict: dict[str, Any] | None = None,
        retry_count: int | None = None,
        error_message: str | None = None,
        completed_at: str | None = None,
        disk_buffer_path: str | None = None,
    ) -> None:
        internal_id = self.resolve_event_id(event_id)
        if internal_id is None:
            return
        updates = []
        values: list[Any] = []
        if processing_status is not None:
            updates.append("processing_status=?")
            values.append(processing_status)
        if association_status is not None:
            updates.append("association_status=?")
            values.append(association_status)
        if rule_status is not None:
            updates.append("rule_status=?")
            values.append(rule_status)
        if llm_status is not None:
            updates.append("llm_status=?")
            values.append(llm_status)
        if rule_verdict is not None:
            updates.append("rule_verdict_json=?")
            values.append(json.dumps(rule_verdict, ensure_ascii=False))
        if llm_verdict is not None:
            updates.append("llm_verdict_json=?")
            values.append(json.dumps(llm_verdict, ensure_ascii=False))
        if retry_count is not None:
            updates.append("retry_count=?")
            values.append(retry_count)
        if error_message is not None:
            updates.append("error_message=?")
            values.append(error_message)
        if completed_at is not None:
            updates.append("completed_at=?")
            values.append(completed_at)
        if disk_buffer_path is not None:
            updates.append("disk_buffer_path=?")
            values.append(disk_buffer_path)
        if not updates:
            return
        values.append(internal_id)
        with self._connect() as connection:
            connection.execute(f"UPDATE events SET {', '.join(updates)} WHERE id=?", values)

    def list_events(
        self,
        limit: int = 100,
        offset: int = 0,
        source_id: str | None = None,
        processing_status: str | None = None,
        association_status: str | None = None,
        is_historical: bool | None = None,
        is_realtime: bool | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        clauses = []
        params: list[Any] = []
        if source_id:
            clauses.append("source_id=?")
            params.append(source_id)
        status_val = processing_status or status
        if status_val:
            clauses.append("processing_status=?")
            params.append(status_val)
        if association_status:
            clauses.append("association_status=?")
            params.append(association_status)
        if is_historical is not None:
            clauses.append("is_realtime=?")
            params.append(0 if is_historical else 1)
        elif is_realtime is not None:
            clauses.append("is_realtime=?")
            params.append(1 if is_realtime else 0)

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        count_query = f"SELECT COUNT(*) FROM events{where}"
        data_query = f"SELECT * FROM events{where} ORDER BY received_at DESC LIMIT ? OFFSET ?"

        with self._connect() as connection:
            total = connection.execute(count_query, params).fetchone()[0]
            query_params = list(params)
            query_params.extend([min(limit, 500), max(0, offset)])
            rows = connection.execute(data_query, query_params).fetchall()

            event_ids = [r["id"] for r in rows]
            alerts_by_event: dict[str, list[dict[str, Any]]] = {}
            if event_ids:
                placeholders = ", ".join("?" for _ in event_ids)
                alert_rows = connection.execute(
                    f"SELECT id, event_id, severity, title, channel_source, status FROM alerts WHERE event_id IN ({placeholders})",
                    event_ids,
                ).fetchall()
                for ar in alert_rows:
                    eid = ar["event_id"]
                    if eid not in alerts_by_event:
                        alerts_by_event[eid] = []
                    alerts_by_event[eid].append({
                        "id": ar["id"],
                        "severity": ar["severity"],
                        "title": ar["title"],
                        "channel_source": ar["channel_source"],
                        "status": ar["status"],
                    })

        items = []
        for r in rows:
            rule_verdict = json.loads(r["rule_verdict_json"] or "null")
            llm_verdict = json.loads(r["llm_verdict_json"] or "null")
            metadata = json.loads(r["metadata_json"] or "{}")
            response_evidence = json.loads(r["response_evidence_json"] or "[]")
            items.append({
                "id": r["id"],
                "internal_id": r["id"],
                "event_id": r["external_event_id"] or r["id"],
                "external_event_id": r["external_event_id"] or r["id"],
                "source_id": r["source_id"],
                "call_id": r["call_id"],
                "attempt_id": r["attempt_id"],
                "event_type": r["event_type"],
                "protocol": r["protocol"],
                "capture_stage": r["capture_stage"],
                "content_integrity": r["content_integrity"],
                "is_realtime": bool(r["is_realtime"]),
                "is_historical": not bool(r["is_realtime"]),
                "timestamp": r["timestamp"],
                "received_at": r["received_at"],
                "payload_hash": r["payload_hash"],
                "disk_buffer_path": r["disk_buffer_path"],
                "processing_status": r["processing_status"],
                "association_status": r["association_status"],
                "rule_status": r["rule_status"],
                "llm_status": r["llm_status"],
                "retry_count": r["retry_count"],
                "error_message": r["error_message"],
                "completed_at": r["completed_at"],
                "rule_verdict": rule_verdict,
                "llm_verdict": llm_verdict,
                "response_evidence": response_evidence,
                "metadata": metadata,
                "alerts": alerts_by_event.get(r["id"], []),
            })
        return {"data": items, "total": total}

    def get_event_detail(self, event_id: str) -> dict[str, Any] | None:
        internal_id = self.resolve_event_id(event_id)
        if internal_id is None:
            return None
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM events WHERE id=?", (internal_id,)).fetchone()
            if not row:
                return None
            tasks = [dict(t) for t in connection.execute(
                "SELECT * FROM event_tasks WHERE event_id=? ORDER BY created_at ASC", (event_id,)
            ).fetchall()]
            alert_rows = connection.execute(
                "SELECT * FROM alerts WHERE event_id=? ORDER BY created_at DESC", (row["id"],)
            ).fetchall()
            alerts = [_alert_row(a) for a in alert_rows]
            correlated = [dict(c) for c in connection.execute(
                """SELECT id, event_type, protocol, capture_stage, content_integrity,
                          processing_status, association_status, received_at
                   FROM events WHERE source_id=? AND call_id=? AND id!=? ORDER BY received_at ASC""",
                (row["source_id"], row["call_id"], row["id"]),
            ).fetchall()]

        rule_verdict = json.loads(row["rule_verdict_json"] or "null")
        llm_verdict = json.loads(row["llm_verdict_json"] or "null")
        metadata = json.loads(row["metadata_json"] or "{}")
        response_evidence = json.loads(row["response_evidence_json"] or "[]")

        return {
            "id": row["id"],
            "internal_id": row["id"],
            "event_id": row["external_event_id"] or row["id"],
            "external_event_id": row["external_event_id"] or row["id"],
            "source_id": row["source_id"],
            "call_id": row["call_id"],
            "attempt_id": row["attempt_id"],
            "event_type": row["event_type"],
            "protocol": row["protocol"],
            "capture_stage": row["capture_stage"],
            "content_integrity": row["content_integrity"],
            "is_realtime": bool(row["is_realtime"]),
            "is_historical": not bool(row["is_realtime"]),
            "timestamp": row["timestamp"],
            "received_at": row["received_at"],
            "payload_hash": row["payload_hash"],
            "disk_buffer_path": row["disk_buffer_path"],
            "processing_status": row["processing_status"],
            "association_status": row["association_status"],
            "rule_status": row["rule_status"],
            "llm_status": row["llm_status"],
            "retry_count": row["retry_count"],
            "error_message": row["error_message"],
            "completed_at": row["completed_at"],
            "rule_verdict": rule_verdict,
            "llm_verdict": llm_verdict,
            "response_evidence": response_evidence,
            "metadata": metadata,
            "tasks": tasks,
            "alerts": alerts,
            "correlated_events": correlated,
        }

    def get_queue_stats(self) -> dict[str, Any]:
        with self._connect() as connection:
            oldest_row = connection.execute(
                "SELECT received_at FROM events WHERE processing_status IN ('pending', 'processing') ORDER BY received_at ASC LIMIT 1"
            ).fetchone()
            rule_pending = connection.execute(
                "SELECT COUNT(*) FROM events WHERE rule_status IN ('pending', 'processing')"
            ).fetchone()[0]
            reviewer_pending = connection.execute(
                "SELECT COUNT(*) FROM events WHERE llm_status IN ('pending', 'processing')"
            ).fetchone()[0]
            failed_count = connection.execute(
                "SELECT COUNT(*) FROM events WHERE processing_status='failed'"
            ).fetchone()[0]

        oldest_age = None
        if oldest_row and oldest_row[0]:
            try:
                dt_str = oldest_row[0].replace("Z", "+00:00")
                recv_dt = datetime.fromisoformat(dt_str)
                now_dt = datetime.now(timezone.utc)
                oldest_age = max(0.0, round((now_dt - recv_dt).total_seconds(), 2))
            except Exception:
                oldest_age = 0.0

        return {
            "db_rule_queue_depth": rule_pending,
            "db_reviewer_queue_depth": reviewer_pending,
            "oldest_pending_task_age_seconds": oldest_age,
            "failed_events_count": failed_count,
        }

    def create_event_alert(
        self,
        *,
        event_id: str,
        severity: str,
        rule_severity: str | None,
        llm_severity: str | None = None,
        llm_status: str = "pending",
        divergence: bool = False,
        channel_source: str = "rule",
        reason_code: str,
        title: str,
        reason: str,
        evidence: list[Any] | None = None,
        evidence_id: str | None = None,
        data_findings: list[Any] | None = None,
        destination: dict[str, Any] | None = None,
    ) -> str:
        # One aggregate alert belongs to one internal event. A deterministic ID
        # makes retries and crash recovery idempotent while preserving any
        # operator acknowledgement fields on the existing row.
        internal_id = self.resolve_event_id(event_id) or event_id
        alert_id = "event-alert-" + hashlib.sha256(internal_id.encode("utf-8")).hexdigest()
        now = _now()
        with self._connect() as connection:
            current_event = connection.execute(
                "SELECT source_id, call_id, event_type, capture_stage, is_realtime, attempt_id, body_hash FROM events WHERE id=?",
                (internal_id,),
            ).fetchone()
            existing = connection.execute(
                "SELECT id FROM alerts WHERE event_id=? ORDER BY created_at ASC LIMIT 1",
                (internal_id,),
            ).fetchone()
            if existing is not None:
                return str(existing["id"])
            # A full_call envelope and its separately submitted request can
            # represent the same observation. Reuse the existing aggregate
            # alert when their source, call and canonical event hash agree.
            if current_event is not None and current_event["event_type"] in {"request", "full_call"}:
                overlap = connection.execute(
                    """SELECT a.id FROM alerts a JOIN events e ON e.id=a.event_id
                       WHERE e.source_id=? AND e.call_id=? AND e.capture_stage=? AND e.is_realtime=?
                         AND (e.attempt_id=? OR (e.attempt_id IS NULL AND ? IS NULL)) AND e.body_hash=?
                         AND e.event_type IN ('request', 'full_call')
                       ORDER BY a.created_at ASC LIMIT 1""",
                    (
                        current_event["source_id"], current_event["call_id"], current_event["capture_stage"],
                        current_event["is_realtime"], current_event["attempt_id"], current_event["attempt_id"],
                        current_event["body_hash"],
                    ),
                ).fetchone()
                if overlap is not None:
                    return str(overlap["id"])
            try:
                connection.execute(
                """INSERT INTO alerts (
                    id, trace_id, classification_run_id, session_record_id, created_at, severity,
                    status, reason_code, title, reason, evidence_json, actions_json, matched_rules_json,
                    final_stage, evidence_id, data_findings_json, destination_json,
                    rule_severity, llm_severity, llm_status, divergence, channel_source, event_id
                ) VALUES (?, ?, ?, NULL, ?, ?, 'open', ?, ?, ?, ?, '[]', '[]', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    alert_id,
                    internal_id,
                    f"event:{internal_id}",
                    now,
                    severity,
                    reason_code,
                    title,
                    reason,
                    json.dumps(_sanitize_event_metadata(evidence or []), ensure_ascii=False),
                    channel_source,
                    evidence_id,
                    json.dumps(_sanitize_event_metadata(data_findings or []), ensure_ascii=False),
                    json.dumps(_sanitize_event_metadata(destination or {}), ensure_ascii=False),
                    rule_severity,
                    llm_severity,
                    llm_status,
                    int(divergence),
                    channel_source,
                    internal_id,
                ),
                )
            except sqlite3.IntegrityError:
                # Another worker can win the same deterministic insert.
                existing = connection.execute(
                    "SELECT id FROM alerts WHERE event_id=? ORDER BY created_at ASC LIMIT 1",
                    (internal_id,),
                ).fetchone()
                if existing is not None:
                    return str(existing["id"])
                raise
            connection.execute(
                "UPDATE alerts SET review_status=?, hit_source=? WHERE id=?",
                (
                    "pending" if llm_status in {"pending", "processing"} else "failed" if llm_status == "failed" else "resolved",
                    "dual" if channel_source == "dual" else "llm_only" if channel_source == "llm" else "rule_only",
                    alert_id,
                ),
            )
        return alert_id

    def update_event_alert_llm(
        self,
        event_id: str,
        *,
        llm_severity: str,
        llm_status: str,
        divergence: bool,
        overall_severity: str | None = None,
    ) -> None:
        internal_id = self.resolve_event_id(event_id) or event_id
        with self._connect() as connection:
            existing = connection.execute("SELECT rule_severity, channel_source FROM alerts WHERE event_id=?", (internal_id,)).fetchone()
            rule_sev = existing["rule_severity"] if existing else None
            is_dual = bool(rule_sev in ("medium", "high", "critical") and llm_severity in ("medium", "high", "critical"))
            channel = "dual" if is_dual else ("rule" if rule_sev in ("medium", "high", "critical") else "llm")
            if overall_severity:
                connection.execute(
                    """UPDATE alerts SET llm_severity=?, llm_status=?, divergence=?, severity=?, channel_source=?
                       WHERE event_id=?""",
                    (llm_severity, llm_status, int(divergence), overall_severity, channel, internal_id),
                )
            else:
                connection.execute(
                    """UPDATE alerts SET llm_severity=?, llm_status=?, divergence=?, channel_source=?
                       WHERE event_id=?""",
                    (llm_severity, llm_status, int(divergence), channel, internal_id),
                )

    def update_event_alert(
        self,
        event_id: str,
        *,
        verdict: dict[str, Any],
        llm_result: dict[str, Any] | None = None,
    ) -> str | None:
        """Idempotently commit a dual-channel event verdict and alert.

        The event worker calls this after persisting each channel result. It
        updates one stable alert row and creates it for an LLM-only hit.
        """
        internal_id = self.resolve_event_id(event_id) or event_id
        llm_result = llm_result or {}
        alert = bool(verdict.get("alert"))
        if not alert:
            return None
        rule_severity = verdict.get("rule_severity")
        llm_severity = verdict.get("llm_severity")
        llm_status = verdict.get("llm_status") or llm_result.get("llm_status") or "pending"
        hit_source = verdict.get("hit_source")
        channel_source = "dual" if hit_source == "dual" else ("llm" if hit_source == "llm_only" else "rule")
        event = self.get_event(internal_id)
        rule_result = json.loads(event.get("rule_verdict_json") or "{}") if event else {}
        alert_id = self.create_event_alert(
            event_id=internal_id,
            severity=verdict.get("severity") or rule_severity or llm_severity or "medium",
            rule_severity=rule_severity,
            llm_severity=llm_severity,
            llm_status=llm_status,
            divergence=bool(verdict.get("divergence")),
            channel_source=channel_source,
            reason_code=str(verdict.get("reason_code") or "EVENT_REVIEW"),
            title=f"{str(verdict.get('severity') or 'medium').upper()}: Outbound Data Review Hit",
            reason=str(verdict.get("reason") or "Outbound event review identified risk"),
            evidence_id=rule_result.get("evidence_id") or llm_result.get("evidence_id"),
            data_findings=rule_result.get("data_findings") or verdict.get("data_findings") or [],
            destination=rule_result.get("destination") or verdict.get("destination") or {},
        )
        with self._connect() as connection:
            connection.execute(
                """UPDATE alerts SET severity=?, rule_severity=?, llm_severity=?, llm_status=?,
                   review_status=?, divergence=?, hit_source=?, channel_source=? WHERE id=?""",
                (
                    verdict.get("severity") or rule_severity or llm_severity or "medium",
                    rule_severity, llm_severity, llm_status,
                    verdict.get("review_status") or "pending", int(bool(verdict.get("divergence"))),
                    hit_source, channel_source, alert_id,
                ),
            )
        return alert_id


def _public_row(row: sqlite3.Row, include_raw: bool = False) -> dict[str, Any]:
    result = dict(row)
    for field in ("request_headers_json", "classification_json", "session_evidence_json"):
        result[field.removesuffix("_json")] = json.loads(result.pop(field) or "null")
    if result["classification"] is None:
        result["classification"] = {"decision": "pending", "proposed_tool_calls": []}
    elif isinstance(result["classification"], dict):
        result["classification"].setdefault("proposed_tool_calls", [])
    raw = result.pop("request_body_json")
    response_raw = result.pop("response_body_json", None)
    if include_raw:
        result["request_body"] = json.loads(raw) if raw else None
        result["response_body"] = json.loads(response_raw) if response_raw else None
    result["is_stream"] = bool(result["is_stream"])
    return result


def _record_response_body(body: bytes | None, content_type: str, complete: bool) -> Any:
    if body is None:
        return None
    text = body.decode("utf-8", "replace")
    try:
        value: Any = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        value = {"raw": text, "stream": "text/event-stream" in content_type.lower()}
    return {"content_type": content_type, "capture_complete": bool(complete), "data": _sanitize_payload(value)}


RULE_FIELDS = {
    "name", "original_text", "scope", "conditions", "effect", "priority",
    "reason_code", "reason",
}


def validate_rule(value: dict[str, Any]) -> None:
    if not isinstance(value, dict):
        raise ValueError("rule must be an object")
    unknown = set(value) - RULE_FIELDS
    if unknown:
        raise ValueError(f"unknown rule fields: {', '.join(sorted(unknown))}")
    required = {"name", "original_text", "scope", "conditions", "effect", "reason_code", "reason"}
    missing = required - set(value)
    if missing:
        raise ValueError(f"missing rule fields: {', '.join(sorted(missing))}")
    if value["effect"] not in {"safe", "escalate", "always_alert"}:
        raise ValueError("invalid rule effect")
    if not isinstance(value["reason_code"], str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", value["reason_code"]):
        raise ValueError("reason_code must be a stable uppercase identifier")
    scope = value["scope"]
    conditions = value["conditions"]
    if not isinstance(scope, dict) or set(scope) - {"protocols", "models", "tools"}:
        raise ValueError("invalid rule scope")
    if not isinstance(conditions, dict) or set(conditions) - {"capabilities", "target_environment", "target_contains"}:
        raise ValueError("invalid rule conditions")
    protocols = scope.get("protocols", [])
    allowed_protocols = {"*", "anthropic_messages", "openai_chat_completions", "openai_responses"}
    if not isinstance(protocols, list) or any(item not in allowed_protocols for item in protocols):
        raise ValueError("unrecognized protocol scope")
    capabilities = conditions.get("capabilities", [])
    if not isinstance(capabilities, list) or any(item not in {"read", "write", "execute", "delete", "publish", "unknown"} for item in capabilities):
        raise ValueError("invalid capabilities")
    serialized = json.dumps(value, ensure_ascii=False)
    if re.search(r"(?:```|\b(?:SELECT|INSERT|UPDATE|DELETE)\s+\w+|\b(?:python|javascript|bash|sh)\s+-c\b|__import__|subprocess\.)", serialized, re.I):
        raise ValueError("executable code, SQL, and shell are not allowed")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _upsert_session(
    connection: sqlite3.Connection,
    *,
    external_session_id: str | None,
    conversation_fingerprint: str | None,
    incoming_messages: list[dict[str, Any]],
    fallback_id: str,
    created_at: str,
    protocol: str,
    model: str | None,
    client_type: str,
) -> str:
    """Resolve the session a trace belongs to, by priority:

    1. explicit session id (header / metadata / conversation chain) — authoritative;
    2. conversation fingerprint — a content-derived identity matched against recent
       sessions of the same opener, reused only when the incoming messages are a
       verified continuation of the session's last trace;
    3. trace fallback — one session per request when nothing else is available.
    """
    if external_session_id:
        row = connection.execute("SELECT * FROM sessions WHERE external_session_id=?", (external_session_id,)).fetchone()
        if row:
            return _touch_session(connection, row, created_at, protocol, model, conversation_fingerprint)
        return _insert_session(
            connection, external_session_id=external_session_id, fingerprint=conversation_fingerprint,
            created_at=created_at, protocol=protocol, model=model, client_type=client_type,
        )

    if conversation_fingerprint:
        candidate = connection.execute(
            "SELECT * FROM sessions WHERE conversation_fingerprint=? ORDER BY last_seen_at DESC LIMIT 1",
            (conversation_fingerprint,),
        ).fetchone()
        if candidate and _fingerprint_session_compatible(connection, candidate["id"], incoming_messages):
            return _touch_session(connection, candidate, created_at, protocol, model, conversation_fingerprint)
        return _insert_session(
            connection, external_session_id=None, fingerprint=conversation_fingerprint,
            created_at=created_at, protocol=protocol, model=model, client_type=client_type,
        )

    row = connection.execute("SELECT * FROM sessions WHERE external_session_id=?", (fallback_id,)).fetchone()
    if row:
        return _touch_session(connection, row, created_at, protocol, model, None)
    return _insert_session(
        connection, external_session_id=fallback_id, fingerprint=None,
        created_at=created_at, protocol=protocol, model=model, client_type=client_type,
    )


def _touch_session(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
    created_at: str,
    protocol: str,
    model: str | None,
    fingerprint: str | None,
) -> str:
    protocols = list(dict.fromkeys([*json.loads(row["protocols_json"]), protocol]))
    models = list(dict.fromkeys([*json.loads(row["models_json"]), *([model] if model else [])]))
    connection.execute(
        """UPDATE sessions SET last_seen_at=?, protocols_json=?, models_json=?,
           call_count=call_count+1, conversation_fingerprint=COALESCE(?, conversation_fingerprint) WHERE id=?""",
        (created_at, json.dumps(protocols), json.dumps(models), fingerprint, row["id"]),
    )
    return str(row["id"])


def _insert_session(
    connection: sqlite3.Connection,
    *,
    external_session_id: str | None,
    fingerprint: str | None,
    created_at: str,
    protocol: str,
    model: str | None,
    client_type: str,
) -> str:
    session_id = str(uuid.uuid4())
    connection.execute(
        """INSERT INTO sessions (
            id, external_session_id, created_at, last_seen_at, client_type,
            protocols_json, models_json, call_count, conversation_fingerprint
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)""",
        (session_id, external_session_id, created_at, created_at, client_type,
         json.dumps([protocol]), json.dumps([model] if model else []), fingerprint),
    )
    return session_id


def _fingerprint_session_compatible(
    connection: sqlite3.Connection,
    session_record_id: str,
    incoming_messages: list[dict[str, Any]],
) -> bool:
    """A fingerprint match is reused only when the conversation provably continues.

    With raw bodies stored, verify the session's last trace messages are a prefix of
    the incoming messages. Without raw bodies, fall back to a recency window so a
    stale same-opener session does not swallow a brand-new conversation.
    """
    if not incoming_messages:
        return True
    row = connection.execute(
        """SELECT request_body_json FROM traces
           WHERE session_record_id=? AND request_body_json IS NOT NULL
           ORDER BY created_at DESC LIMIT 1""",
        (session_record_id,),
    ).fetchone()
    if row is None:
        last_seen = connection.execute("SELECT last_seen_at FROM sessions WHERE id=?", (session_record_id,)).fetchone()
        if last_seen is None:
            return False
        try:
            seen = datetime.fromisoformat(last_seen[0])
        except (ValueError, TypeError):
            return False
        window_hours = float(os.getenv("AUTOMODE_SESSION_FINGERPRINT_WINDOW_HOURS", "72"))
        return (datetime.now(timezone.utc) - seen).total_seconds() <= window_hours * 3600
    try:
        previous = json.loads(row[0])
    except json.JSONDecodeError:
        return True
    previous_messages = extract_messages(previous)
    if not previous_messages:
        return True
    # Same conversation lineage: one message list is a prefix of the other. The
    # reverse direction matters when re-grouping historical traces out of order,
    # where an older (shorter) trace is checked against a session whose latest
    # trace is newer.
    return (
        messages_are_continuation(previous_messages, incoming_messages)
        or messages_are_continuation(incoming_messages, previous_messages)
    )


def _merge_authorization_values(current: dict[str, Any], signals: dict[str, Any]) -> dict[str, Any]:
    """Pure merge of per-request authorization signals into a session baseline.

    Capabilities and constraints accumulate (standing instructions stay in force for
    the session); statements are deduplicated by text and bounded to the most recent.
    """
    capabilities = list(dict.fromkeys([*current.get("capabilities", []), *signals.get("capabilities", [])]))
    forbidden = list(dict.fromkeys([*current.get("forbidden_capabilities", []), *signals.get("forbidden_capabilities", [])]))
    statements = list(current.get("statements", []))
    seen = {_statement_key(item) for item in statements}
    for item in signals.get("statements", []) or []:
        key = _statement_key(item)
        if key in seen:
            continue
        seen.add(key)
        statements.append(item)
    return {"capabilities": capabilities, "forbidden_capabilities": forbidden, "statements": statements[-40:]}


def _merge_authorization(
    connection: sqlite3.Connection,
    session_record_id: str,
    signals: dict[str, Any],
) -> dict[str, Any]:
    row = connection.execute("SELECT authorization_json FROM sessions WHERE id=?", (session_record_id,)).fetchone()
    current = json.loads(row[0] or "{}") if row and row[0] else {}
    return _merge_authorization_values(current, signals)


def _statement_key(item: Any) -> str:
    if not isinstance(item, dict):
        return str(item)
    return hashlib.sha256(str(item.get("text", "")).encode()).hexdigest()


def _client_type(headers: dict[str, str]) -> str:
    agent = headers.get("user-agent", "").lower()
    if "claude" in agent:
        return "claude_code"
    if "openai" in agent or "codex" in agent:
        return "openai_agent"
    return "unknown"


def _max_risk_sql(connection: sqlite3.Connection, session_id: str, risk: str) -> str:
    row = connection.execute("SELECT max_risk FROM sessions WHERE id=?", (session_id,)).fetchone()
    order = ["low", "medium", "high", "critical"]
    current = row[0] if row and row[0] in order else "low"
    return order[max(order.index(current), order.index(risk))]


def _alert_title(result: dict[str, Any]) -> str:
    if result.get("review_object") == "outbound_request":
        categories = sorted({str(item.get("category")) for item in result.get("data_findings", [])})
        return f"{result['risk'].upper()}: outbound {', '.join(categories) or 'data'} requires attention"[:200]
    if result.get("review_object") == "human_request":
        return f"{result['risk'].upper()}: human request requires attention"[:200]
    actions = result.get("proposed_actions", [])
    tool = actions[0].get("name") if actions else "Model action"
    return f"{result['risk'].upper()}: {tool} requires attention"[:200]


def _validate_destination(value: dict[str, Any]) -> None:
    if not str(value.get("name") or "").strip():
        raise ValueError("destination name is required")
    if value.get("trust") not in {"trusted", "external"}:
        raise ValueError("destination trust must be trusted or external")
    for key in ("upstream_pattern", "model_pattern"):
        if len(str(value.get(key, "*"))) > 500:
            raise ValueError(f"{key} is too long")


def _validate_dlp_policy(value: dict[str, Any]) -> None:
    if value.get("effect") not in {"alert", "review"}:
        raise ValueError("DLP policy effect must be alert or review")
    conditions = value.get("conditions")
    if not isinstance(conditions, dict):
        raise ValueError("DLP policy conditions are required")
    allowed_categories = {"credential", "pii", "source_code", "admin_keyword"}
    if set(conditions.get("data_categories") or []) - allowed_categories:
        raise ValueError("unsupported DLP data category")
    if set(conditions.get("destination_trust") or []) - {"trusted", "external"}:
        raise ValueError("unsupported destination trust")


def _dlp_policy_row(row: sqlite3.Row) -> dict[str, Any]:
    value = json.loads(row["compiled_json"])
    return {**value, "id": row["id"], "version": row["current_version"], "enabled": bool(row["enabled"]), "created_at": row["created_at"], "updated_at": row["updated_at"]}


def _without_reasoning(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _without_reasoning(item)
            for key, item in value.items()
            if key.lower() not in {"thinking", "reasoning", "analysis", "chain_of_thought"}
        }
    if isinstance(value, list):
        return [_without_reasoning(item) for item in value]
    return value


def _sanitize_payload(value: Any, key: str = "") -> Any:
    if isinstance(value, dict):
        return {
            item_key: ("[REDACTED]" if _secret_key(item_key) else _sanitize_payload(item, item_key))
            for item_key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_payload(item, key) for item in value]
    if isinstance(value, str):
        return _redact(value)
    return value


def _sanitize_event_metadata(value: Any) -> Any:
    """Keep event metadata useful while ensuring credential-bearing values stay redacted."""
    return _sanitize_payload(value)


_PROJECTION_BODY_KEYS = {
    "payload", "request_body", "response_body", "raw", "body", "messages",
    "tool_result", "input", "output", "prompt", "completion",
}


def _sanitize_projection(value: Any, key: str = "") -> Any:
    """Build a small, redacted analysis read-model without event正文."""
    if isinstance(value, dict):
        return {
            str(item_key): _sanitize_projection(item, str(item_key))
            for item_key, item in value.items()
            if str(item_key).lower() not in _PROJECTION_BODY_KEYS
        }
    if isinstance(value, list):
        return [_sanitize_projection(item, key) for item in value]
    if isinstance(value, str):
        text = _redact(value)
        text = re.sub(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[REDACTED:EMAIL]", text)
        text = re.sub(r"(?<!\d)1[3-9]\d{9}(?!\d)", "[REDACTED:PHONE]", text)
        text = re.sub(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)", "[REDACTED:SSN]", text)
        return text[:2000]
    return value


def _secret_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return normalized in {
        "authorization", "api_key", "x_api_key", "cookie", "set_cookie",
        "proxy_authorization", "password", "secret", "token", "access_token",
        "client_secret", "credential", "credentials", "private_key",
    } or any(part in normalized for part in ("api_key", "access_token", "client_secret", "password", "credential"))


def _redact(value: str) -> str:
    text = str(value)
    patterns = [
        r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]{8,}",
        r"\bsk-[A-Za-z0-9_-]{8,}\b",
        r"(?i)((?:api[_ -]?key|token|password|secret)\s*[:=]\s*)[^\s,;]+",
    ]
    for pattern in patterns:
        text = re.sub(pattern, r"\1[REDACTED]" if "(" in pattern else "[REDACTED]", text)
    return text


def _audit(connection: sqlite3.Connection, action: str, entity_type: str, entity_id: str | None, detail: dict[str, Any]) -> None:
    connection.execute(
        "INSERT INTO audit_log VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), _now(), action, entity_type, entity_id, json.dumps(detail, ensure_ascii=False)),
    )


def _json_row(row: sqlite3.Row, json_fields: tuple[str, ...]) -> dict[str, Any]:
    result = dict(row)
    for field in json_fields:
        value = result.pop(field, None)
        result[field.removesuffix("_json")] = json.loads(value or "null")
    return result


def _rule_row(row: sqlite3.Row) -> dict[str, Any]:
    value = json.loads(row["compiled_json"])
    value.update({
        "id": row["id"], "name": row["name"], "original_text": row["original_text"],
        "version": row["current_version"], "enabled": bool(row["enabled"]),
        "created_at": row["created_at"], "updated_at": row["updated_at"],
    })
    return value


def _alert_row(row: sqlite3.Row) -> dict[str, Any]:
    value = _json_row(row, ("evidence_json", "actions_json", "matched_rules_json", "data_findings_json", "destination_json"))
    findings = value.get("data_findings") or []
    reason_code = str(value.get("reason_code") or "")
    is_dlp = bool(findings or "DLP" in reason_code or "SENSITIVE" in reason_code)
    value["alert_type"] = "dlp" if is_dlp else "intent_action"
    value["data_categories"] = sorted({str(f.get("category")) for f in findings if isinstance(f, dict) and f.get("category")})
    destination = value.get("destination") or {}
    value["destination_name"] = destination.get("name") or destination.get("model") or "未知模型"
    value["destination_trust"] = destination.get("trust", "external")
    value["divergence"] = bool(value.get("divergence"))
    value["review_status"] = value.get("review_status") or "resolved"
    if not value.get("channel_source"):
        value["channel_source"] = "legacy"
    if not value.get("rule_severity"):
        value["rule_severity"] = value.get("severity")
    return value


def _session_risk_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"], "session_id": row["session_id"], "trace_id": row["trace_id"],
        "started_at": row["started_at"], "ended_at": row["ended_at"],
        "purpose_risk": row["purpose_risk"], "transfer_intent": row["transfer_intent"],
        "severity": row["severity"], "state": row["state"], "reason_code": row["reason_code"],
        "summary": row["summary"], "source": row["source"], "version": row["version"],
        "alert_id": row["alert_id"],
    }


def _tool_action_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "tool_name": row["tool_name"],
        "arguments": json.loads(row["arguments_json"] or "null"),
        "capability": row["capability"],
        "target": row["target"],
        "side_effect": row["side_effect"],
        "risk": row["risk"],
        "action_hash": row["action_hash"],
        "created_at": row["created_at"],
    }


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    index = min(len(values) - 1, max(0, round((len(values) - 1) * fraction)))
    return round(values[index], 3)
