from __future__ import annotations

import json
import hashlib
import os
import re
import shutil
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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
    max_risk TEXT NOT NULL DEFAULT 'low'
);
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
    error TEXT
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
    id TEXT PRIMARY KEY, trace_id TEXT NOT NULL, classification_run_id TEXT NOT NULL,
    session_record_id TEXT, created_at TEXT NOT NULL, severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open', reason_code TEXT NOT NULL, title TEXT NOT NULL,
    reason TEXT NOT NULL, evidence_json TEXT NOT NULL, actions_json TEXT NOT NULL,
    matched_rules_json TEXT NOT NULL, final_stage TEXT NOT NULL,
    acknowledged_at TEXT, operator_note TEXT, feedback TEXT,
    FOREIGN KEY(trace_id) REFERENCES traces(id)
);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC);
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
"""

TRACE_COLUMNS = {
    "session_record_id": "TEXT",
    "pipeline_status": "TEXT NOT NULL DEFAULT 'pending'",
    "final_decision": "TEXT",
    "final_stage": "TEXT",
    "final_reason_code": "TEXT",
    "final_reason": "TEXT",
}

STAGE_COLUMNS = {
    "matched_rule_versions_json": "TEXT NOT NULL DEFAULT '[]'",
    "evidence_json": "TEXT NOT NULL DEFAULT '[]'",
}

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
    def __init__(self, path: str | Path, store_raw: bool = True) -> None:
        self.path = str(path)
        self.store_raw = store_raw
        self._initialize()

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
            if (trace_columns and set(TRACE_COLUMNS) - trace_columns) or (stage_columns and set(STAGE_COLUMNS) - stage_columns):
                backup = database.with_name(f"{database.name}.pre-automode-migration.bak")
                shutil.copy2(database, backup)
        try:
            with self._connect() as connection:
                connection.executescript(SCHEMA)
                for table, columns in (("traces", TRACE_COLUMNS), ("classification_stages", STAGE_COLUMNS)):
                    existing = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
                    for name, definition in columns.items():
                        if name not in existing:
                            connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
                connection.execute("PRAGMA journal_mode=WAL")
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
    ) -> str:
        trace_id = trace_id or str(uuid.uuid4())
        created_at = _now()
        safe_headers = {
            key: ("[REDACTED]" if key.lower() in SECRET_HEADERS else value)
            for key, value in headers.items()
        }
        with self._connect() as connection:
            session_record_id = _upsert_session(
                connection,
                external_session_id=session_id,
                fallback_id=f"trace:{trace_id}",
                created_at=created_at,
                protocol=protocol,
                model=payload.get("model"),
                client_type=_client_type(headers),
            )
            connection.execute(
                """INSERT INTO traces (
                    id, created_at, protocol, method, path, model, session_id, is_stream,
                    latest_user_text, declared_tool_count, request_headers_json, request_body_json,
                    session_record_id, pipeline_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')""",
                (
                    trace_id,
                    created_at,
                    protocol,
                    method,
                    path,
                    payload.get("model"),
                    session_id,
                    int(bool(payload.get("stream"))),
                    latest_user_text,
                    declared_tool_count,
                    json.dumps(safe_headers, ensure_ascii=False),
                    json.dumps(_sanitize_payload(payload), ensure_ascii=False) if self.store_raw else None,
                    session_record_id,
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
                    action_alignment, reason_code, reason, started_at, completed_at, total_latency_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id, trace_id, json.dumps(result.get("review_transcript", []), ensure_ascii=False),
                    result["final_decision"], result["final_stage"], result["risk"],
                    result["action_alignment"], result["reason_code"], _redact(result["reason"]),
                    started_at, completed_at, float(result.get("total_latency_ms", 0)),
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
                alert_id = str(uuid.uuid4())
                connection.execute(
                    """INSERT INTO alerts (
                        id, trace_id, classification_run_id, session_record_id, created_at, severity,
                        reason_code, title, reason, evidence_json, actions_json, matched_rules_json, final_stage
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        alert_id, trace_id, run_id, session_id, completed_at, result["risk"],
                        result["reason_code"], _alert_title(result), _redact(result["reason"]),
                        json.dumps(result.get("authorization_evidence", []), ensure_ascii=False),
                        json.dumps(result.get("proposed_actions", []), ensure_ascii=False),
                        json.dumps(result.get("matched_rules", []), ensure_ascii=False), result["final_stage"],
                    ),
                )
        return run_id, alert_id

    def finish(
        self,
        trace_id: str,
        *,
        status: int | None,
        response_bytes: int,
        latency_ms: float,
        error: str | None = None,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """UPDATE traces SET response_status=?, response_bytes=?, latency_ms=?, error=?
                   WHERE id=?""",
                (status, response_bytes, latency_ms, error, trace_id),
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

    def sessions(
        self,
        limit: int = 100,
        protocol: str | None = None,
        model: str | None = None,
        risk: str | None = None,
        decision: str | None = None,
        capability: str | None = None,
        since: str | None = None,
    ) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM sessions ORDER BY last_seen_at DESC LIMIT 500").fetchall()
            result = [_json_row(row, ("protocols_json", "models_json")) for row in rows]
            if capability:
                allowed_ids = {row[0] for row in connection.execute(
                    """SELECT DISTINCT t.session_record_id FROM traces t JOIN tool_actions a ON a.trace_id=t.id
                       WHERE a.capability=?""", (capability,)
                )}
                result = [row for row in result if row["id"] in allowed_ids]
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
        return result[:min(max(limit, 1), 500)]

    def session(self, session_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        return _json_row(row, ("protocols_json", "models_json")) if row else None

    def timeline(self, session_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            traces = connection.execute("SELECT * FROM traces WHERE session_record_id=? ORDER BY created_at", (session_id,)).fetchall()
            result: list[dict[str, Any]] = []
            for trace in traces:
                result.append({"type": "user_message", "at": trace["created_at"], "trace_id": trace["id"], "text": trace["latest_user_text"]})
                result.append({"type": "model_call", "at": trace["created_at"], "trace_id": trace["id"], "model": trace["model"], "protocol": trace["protocol"]})
                actions = connection.execute("SELECT * FROM tool_actions WHERE trace_id=? ORDER BY created_at", (trace["id"],)).fetchall()
                result.extend({"type": "tool_action", "at": row["created_at"], "trace_id": trace["id"], "tool_name": row["tool_name"], "capability": row["capability"], "target": row["target"]} for row in actions)
                run = connection.execute("SELECT * FROM classification_runs WHERE trace_id=? ORDER BY completed_at DESC LIMIT 1", (trace["id"],)).fetchone()
                if run:
                    stages = connection.execute("SELECT * FROM classification_stages WHERE run_id=? ORDER BY rowid", (run["id"],)).fetchall()
                    result.extend({"type": "classification_stage", "at": run["completed_at"], "trace_id": trace["id"], "stage": row["stage"], "status": row["status"], "verdict": row["verdict"], "reason_code": row["reason_code"], "reason": row["reason"], "model": row["model"], "latency_ms": row["latency_ms"], "risk": row["risk"], "matched_rules": json.loads(row["matched_rule_versions_json"] or "[]"), "evidence": json.loads(row["evidence_json"] or "[]")} for row in stages)
                    result.append({"type": "final_decision", "at": run["completed_at"], "trace_id": trace["id"], "decision": run["final_decision"], "stage": run["final_stage"]})
        return result

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
        result = _json_row(run, ("review_transcript_json",))
        result["stages"] = [_json_row(row, ("matched_rule_ids_json", "matched_rule_versions_json", "evidence_json")) for row in stages]
        return result

    def alerts(self, limit: int = 100, status: str | None = None) -> list[dict[str, Any]]:
        with self._connect() as connection:
            if status:
                rows = connection.execute("SELECT * FROM alerts WHERE status=? ORDER BY created_at DESC LIMIT ?", (status, min(limit, 500))).fetchall()
            else:
                rows = connection.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (min(limit, 500),)).fetchall()
        return [_alert_row(row) for row in rows]

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
        return {
            "trace_count": trace_count, "session_count": session_count, "open_alert_count": alert_count,
            "alert_rate": (decisions.get("alert", 0) / trace_count if trace_count else 0),
            "stage_counts": stages, "decisions": decisions, "top_reasons": reasons,
            "classification_latency_ms": {"p50": _percentile(latencies, 0.50), "p95": _percentile(latencies, 0.95)},
            "health": {
                "gateway": "healthy",
                "upstream": "healthy" if latest_status and latest_status[0] < 500 else "unknown",
                "fast": "configured" if os.getenv("AUTOMODE_FAST_URL") and os.getenv("AUTOMODE_FAST_MODEL") else "not_configured",
                "deep": "configured" if os.getenv("AUTOMODE_DEEP_URL") and os.getenv("AUTOMODE_DEEP_MODEL") else "not_configured",
            },
        }

    def settings(self) -> dict[str, Any]:
        result = {"operating_mode": "observe", "retention_days": 30, "store_raw": self.store_raw}
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


def _public_row(row: sqlite3.Row, include_raw: bool = False) -> dict[str, Any]:
    result = dict(row)
    for field in ("request_headers_json", "classification_json"):
        result[field.removesuffix("_json")] = json.loads(result.pop(field) or "null")
    if result["classification"] is None:
        result["classification"] = {"decision": "pending", "proposed_tool_calls": []}
    raw = result.pop("request_body_json")
    if include_raw:
        result["request_body"] = json.loads(raw) if raw else None
    result["is_stream"] = bool(result["is_stream"])
    return result


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
    fallback_id: str,
    created_at: str,
    protocol: str,
    model: str | None,
    client_type: str,
) -> str:
    external = external_session_id or fallback_id
    row = connection.execute("SELECT * FROM sessions WHERE external_session_id=?", (external,)).fetchone()
    if row:
        protocols = list(dict.fromkeys([*json.loads(row["protocols_json"]), protocol]))
        models = list(dict.fromkeys([*json.loads(row["models_json"]), *([model] if model else [])]))
        connection.execute(
            "UPDATE sessions SET last_seen_at=?, protocols_json=?, models_json=?, call_count=call_count+1 WHERE id=?",
            (created_at, json.dumps(protocols), json.dumps(models), row["id"]),
        )
        return str(row["id"])
    session_id = str(uuid.uuid4())
    connection.execute(
        """INSERT INTO sessions (
            id, external_session_id, created_at, last_seen_at, client_type,
            protocols_json, models_json, call_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)""",
        (session_id, external, created_at, created_at, client_type, json.dumps([protocol]), json.dumps([model] if model else [])),
    )
    return session_id


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
    actions = result.get("proposed_actions", [])
    tool = actions[0].get("name") if actions else "Model action"
    return f"{result['risk'].upper()}: {tool} requires attention"[:200]


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


def _secret_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return normalized in {"authorization", "api_key", "x_api_key", "cookie", "proxy_authorization", "password", "secret", "token"}


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
    return _json_row(row, ("evidence_json", "actions_json", "matched_rules_json"))


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    index = min(len(values) - 1, max(0, round((len(values) - 1) * fraction)))
    return round(values[index], 3)
