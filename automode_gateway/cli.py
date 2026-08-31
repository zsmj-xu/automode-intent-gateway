from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, TextIO

from .gateway import run_gateway
from .service import classify_payload


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="auto-intent", description="Classify LiteLLM request logs")
    sub = parser.add_subparsers(dest="command", required=True)

    classify_cmd = sub.add_parser("classify", help="classify one JSON object or a JSONL stream")
    classify_cmd.add_argument("input", nargs="?", default="-", help="JSON/JSONL file, or - for stdin")
    classify_cmd.add_argument("--jsonl", action="store_true", help="read and emit one JSON object per line")

    serve_cmd = sub.add_parser("serve", help="start the transparent dual-protocol gateway")
    serve_cmd.add_argument("--host", default="127.0.0.1")
    serve_cmd.add_argument("--port", default=8787, type=int)
    serve_cmd.add_argument(
        "--upstream",
        default=os.getenv("AUTOMODE_UPSTREAM_BASE_URL"),
        help="upstream base URL, or set AUTOMODE_UPSTREAM_BASE_URL",
    )
    serve_cmd.add_argument("--db", default=os.getenv("AUTOMODE_DB", "automode.db"))
    serve_cmd.add_argument(
        "--no-store-raw",
        action="store_true",
        help="do not persist complete request JSON",
    )

    backfill_cmd = sub.add_parser("backfill", help="regroup historical traces into conversation sessions")
    backfill_cmd.add_argument("--db", default=os.getenv("AUTOMODE_DB", "automode.db"))
    key_cmd = sub.add_parser("evidence-key", help="generate a local AES-256 evidence key file")
    key_cmd.add_argument("path", help="new key file path")
    migrate_cmd = sub.add_parser("migrate-evidence", help="encrypt sensitive historical request bodies and replace them with redacted copies")
    migrate_cmd.add_argument("--db", default=os.getenv("AUTOMODE_DB", "automode.db"))
    migrate_cmd.add_argument("--key-file", required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    if args.command == "serve":
        if not args.upstream:
            raise SystemExit("--upstream or AUTOMODE_UPSTREAM_BASE_URL is required")
        run_gateway(args.host, args.port, args.upstream, args.db, not args.no_store_raw)
        return

    if args.command == "backfill":
        from .storage import TraceStore

        stats = TraceStore(args.db).backfill_sessions()
        print(json.dumps(stats, ensure_ascii=False, indent=2))
        return

    if args.command == "evidence-key":
        from .evidence import generate_key

        path = Path(args.path)
        if path.exists():
            raise SystemExit(f"refusing to overwrite existing key file: {path}")
        path.touch(mode=0o600, exist_ok=False)
        path.write_text(generate_key() + "\n", encoding="ascii")
        os.chmod(path, 0o600)
        print(str(path.resolve()))
        return

    if args.command == "migrate-evidence":
        from .evidence import load_key
        from .storage import TraceStore

        stats = TraceStore(args.db, evidence_key=load_key(args.key_file)).migrate_legacy_evidence()
        print(json.dumps(stats, ensure_ascii=False, indent=2))
        return

    stream: TextIO
    if args.input == "-":
        stream = sys.stdin
    else:
        stream = Path(args.input).open(encoding="utf-8")
    try:
        if args.jsonl:
            _classify_jsonl(stream)
        else:
            payload = json.load(stream)
            print(json.dumps(classify_payload(payload), ensure_ascii=False, indent=2))
    finally:
        if stream is not sys.stdin:
            stream.close()


def _classify_jsonl(stream: TextIO) -> None:
    for line_number, line in enumerate(stream, 1):
        if not line.strip():
            continue
        try:
            result: dict[str, Any] = classify_payload(json.loads(line))
        except Exception as exc:
            result = {"error": "invalid_event", "line": line_number, "message": str(exc)}
        print(json.dumps(result, ensure_ascii=False))
