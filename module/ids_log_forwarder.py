#!/usr/bin/env python3

# Backend Dockerfile should contain: RUN pip install pika

import os
import re
import json
import time
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)

    if value is None:
        return default

    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def env_int(name: str, default: int) -> int:
    value = os.getenv(name)

    if value is None or not value.strip():
        return default

    try:
        return int(value)
    except ValueError as exc:
        raise SystemExit(f"{name} must be an integer: {value!r}") from exc


def env_float(name: str, default: float) -> float:
    value = os.getenv(name)

    if value is None or not value.strip():
        return default

    try:
        return float(value)
    except ValueError as exc:
        raise SystemExit(f"{name} must be a number: {value!r}") from exc


# Log and rule paths
SNORT_ALERT_FILE = os.getenv("SNORT_ALERT_FILE", "/shared/logs/snort/alert")
YARA_LOG_FILE = os.getenv("YARA_LOG_FILE", "/shared/logs/yara/yara_scan.log")
SNORT_RULE_FILE = os.getenv("SNORT_RULE_FILE", "/shared/rules/snort/local.rules")
YARA_RULE_FILE = os.getenv("YARA_RULE_FILE", "/shared/rules/yara/ctink_rules.yar")
STATE_FILE = os.getenv(
    "IDS_LOG_FORWARDER_STATE_FILE",
    "/shared/logs/snort/.ids_log_forwarder_state.json",
)

# RabbitMQ connection
# RABBITMQ_URL takes precedence when both URL and individual variables are set.
RABBITMQ_URL = os.getenv("RABBITMQ_URL", "").strip()
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "").strip()
RABBITMQ_PORT = env_int("RABBITMQ_PORT", 5672)
RABBITMQ_USERNAME = os.getenv("RABBITMQ_USERNAME", "").strip()
RABBITMQ_PASSWORD = os.getenv("RABBITMQ_PASSWORD", "")
RABBITMQ_VHOST = os.getenv("RABBITMQ_VHOST", "/")
RABBITMQ_HEARTBEAT = env_int("RABBITMQ_HEARTBEAT", 60)
RABBITMQ_BLOCKED_CONNECTION_TIMEOUT_SEC = env_float(
    "RABBITMQ_BLOCKED_CONNECTION_TIMEOUT_SEC",
    30.0,
)
IDS_LOG_OUTPUT_QUEUE = os.getenv(
    "IDS_LOG_OUTPUT_QUEUE",
    "log.result.queue",
).strip()

# Forwarder behavior
POLL_INTERVAL_SEC = env_float("IDS_LOG_POLL_INTERVAL_SEC", 2.0)
ERROR_RETRY_INTERVAL_SEC = env_float("IDS_LOG_ERROR_RETRY_INTERVAL_SEC", 5.0)
SEND_UNMATCHED = env_bool("IDS_LOG_SEND_UNMATCHED", True)
MAX_SENT_HASHES = env_int("IDS_LOG_MAX_SENT_HASHES", 5000)


def validate_configuration() -> None:
    if not IDS_LOG_OUTPUT_QUEUE:
        raise SystemExit("IDS_LOG_OUTPUT_QUEUE must not be empty")

    if RABBITMQ_URL:
        return

    missing = []

    if not RABBITMQ_HOST:
        missing.append("RABBITMQ_HOST")
    if not RABBITMQ_USERNAME:
        missing.append("RABBITMQ_USERNAME")
    if not RABBITMQ_PASSWORD:
        missing.append("RABBITMQ_PASSWORD")

    if missing:
        names = ", ".join(missing)
        raise SystemExit(
            "Set RABBITMQ_URL, or set all required individual variables: " + names
        )


def rabbitmq_public_config() -> Dict[str, Any]:
    if RABBITMQ_URL:
        parsed = urlparse(RABBITMQ_URL)
        default_port = 5671 if parsed.scheme == "amqps" else 5672
        encoded_vhost = parsed.path.lstrip("/")
        public_vhost = unquote(encoded_vhost) if encoded_vhost else "/"
        return {
            "connection_mode": "url",
            "rabbitmq_host": parsed.hostname,
            "rabbitmq_port": parsed.port or default_port,
            "rabbitmq_vhost": public_vhost,
        }

    return {
        "connection_mode": "individual_variables",
        "rabbitmq_host": RABBITMQ_HOST,
        "rabbitmq_port": RABBITMQ_PORT,
        "rabbitmq_vhost": RABBITMQ_VHOST,
    }


SNORT_LOG_RE = re.compile(
    r"^(?P<ts>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<msg>.*?)\s+"
    r"\[\*\*\]\s+"
    r"(?:\[Classification:\s+(?P<classification>.*?)\]\s+)?"
    r"\[Priority:\s+(?P<priority>\d+)\]\s+"
    r"\{(?P<protocol>[A-Za-z0-9_]+)\}\s+"
    r"(?P<src>.+?)\s+->\s+(?P<dst>.+?)\s*$"
)

SNORT_RULE_RE = re.compile(
    r"(?ms)\b(?P<action>alert|log|pass|activate|dynamic|drop|reject|sdrop)\s+"
    r".*?"
    r"\(.*?\bsid\s*:\s*(?P<sid>\d+)\s*;.*?\)"
)

YARA_RULE_HEAD_RE = re.compile(
    r"\b(?:private\s+|global\s+)*rule\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


def format_detected_at(value: Any) -> str:
    if value is None:
        return now_iso()

    if isinstance(value, datetime):
        return value.replace(tzinfo=None).isoformat()

    text = str(value).strip()

    if not text:
        return now_iso()

    if text.endswith("Z"):
        text = text[:-1]

    text = re.sub(r"([+-]\d{2}:\d{2})$", "", text)
    return text


def load_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        return ""
    except Exception:
        return ""


def load_state() -> Dict[str, Any]:
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            state = json.load(f)

        if not isinstance(state, dict):
            return {}

        state.setdefault("offsets", {})
        state.setdefault("buffers", {})
        state.setdefault("sent_hashes", [])
        state.setdefault("sent_event_hashes", [])
        return state

    except Exception:
        return {
            "offsets": {},
            "buffers": {},
            "sent_hashes": [],
            "sent_event_hashes": [],
        }


def save_state(state: Dict[str, Any]) -> None:
    path = Path(STATE_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)

    tmp_path = f"{STATE_FILE}.tmp"

    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

    os.replace(tmp_path, STATE_FILE)


def stable_json_hash(obj: Dict[str, Any]) -> str:
    normalized = json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def remember_sent_hash(state: Dict[str, Any], list_name: str, hash_value: str) -> None:
    sent = state.setdefault(list_name, [])

    if hash_value in sent:
        return

    sent.append(hash_value)

    if len(sent) > MAX_SENT_HASHES:
        del sent[: len(sent) - MAX_SENT_HASHES]


def was_sent_hash(state: Dict[str, Any], list_name: str, hash_value: str) -> bool:
    return hash_value in set(state.get(list_name, []))


def build_event_dedupe_hash(payload: Dict[str, Any]) -> str:
    try:
        detail = json.loads(payload.get("detail", "{}"))
    except json.JSONDecodeError:
        detail = {}

    engine = detail.get("engine")

    if engine == "snort":
        key = {
            "engine": "snort",
            "gid": detail.get("gid"),
            "sid": detail.get("sid"),
            "rev": detail.get("rev"),
            "message": detail.get("message"),
            "classification": detail.get("classification"),
            "priority": detail.get("priority"),
            "protocol": detail.get("protocol"),
            "src_ip": detail.get("src_ip"),
            "src_port": detail.get("src_port"),
            "dst_ip": detail.get("dst_ip"),
            "dst_port": detail.get("dst_port"),
            "result": payload.get("result"),
            "rule_content": payload.get("rule_content"),
        }
        return stable_json_hash(key)

    if engine == "yara":
        key = {
            "engine": "yara",
            "rule_name": detail.get("rule_name"),
            "target_path": detail.get("target_path"),
            "rule_file": detail.get("rule_file"),
            "scan_target": detail.get("scan_target"),
            "result": payload.get("result"),
            "rule_content": payload.get("rule_content"),
        }
        return stable_json_hash(key)

    key = {
        "engine": engine,
        "result": payload.get("result"),
        "rule_content": payload.get("rule_content"),
        "detail": payload.get("detail"),
    }
    return stable_json_hash(key)


def read_new_lines(path: str, state: Dict[str, Any]) -> List[str]:
    p = Path(path)

    if not p.exists():
        return []

    offsets = state.setdefault("offsets", {})
    buffers = state.setdefault("buffers", {})

    old_offset = int(offsets.get(path, 0))
    current_size = p.stat().st_size

    if current_size < old_offset:
        old_offset = 0
        buffers[path] = ""

    with open(p, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(old_offset)
        chunk = f.read()
        new_offset = f.tell()

    offsets[path] = new_offset

    if not chunk:
        return []

    previous_buffer = buffers.get(path, "")
    data = previous_buffer + chunk

    if data.endswith("\n"):
        lines = data.splitlines()
        buffers[path] = ""
    else:
        parts = data.splitlines()
        if parts:
            lines = parts[:-1]
            buffers[path] = parts[-1]
        else:
            lines = []
            buffers[path] = data

    return [line for line in lines if line.strip()]


def split_host_port(value: str) -> Tuple[str, Optional[int]]:
    value = value.strip()

    if ":" not in value:
        return value, None

    host, port_text = value.rsplit(":", 1)

    try:
        return host, int(port_text)
    except ValueError:
        return value, None


def parse_snort_time(ts: str) -> str:
    year = datetime.now(timezone.utc).year
    dt = datetime.strptime(f"{year}/{ts}", "%Y/%m/%d-%H:%M:%S.%f")
    return format_detected_at(dt)


def build_snort_rule_map() -> Dict[str, Dict[str, str]]:
    content = load_text(SNORT_RULE_FILE)
    result: Dict[str, Dict[str, str]] = {}

    for match in SNORT_RULE_RE.finditer(content):
        sid = match.group("sid")
        action = match.group("action").lower()
        rule_content = match.group(0).strip()

        result[sid] = {
            "rule_content": rule_content,
            "action": action,
        }

    return result


def extract_yara_rule_block(content: str, start_index: int) -> str:
    brace_start = content.find("{", start_index)

    if brace_start == -1:
        line_end = content.find("\n", start_index)
        if line_end == -1:
            return content[start_index:].strip()
        return content[start_index:line_end].strip()

    depth = 0
    i = brace_start

    while i < len(content):
        ch = content[i]

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1

            if depth == 0:
                return content[start_index : i + 1].strip()

        i += 1

    return content[start_index:].strip()


def build_yara_rule_map() -> Dict[str, str]:
    content = load_text(YARA_RULE_FILE)
    result: Dict[str, str] = {}

    for match in YARA_RULE_HEAD_RE.finditer(content):
        name = match.group("name")
        start = match.start()
        rule_block = extract_yara_rule_block(content, start)
        result[name] = rule_block

    return result


def snort_action_to_result(action: Optional[str]) -> str:
    if not action:
        return "ALERT"

    action = action.lower()

    if action in {"drop", "reject", "sdrop"}:
        return "BLOCK"

    return "ALERT"


def escape_snort_text(value: Any) -> str:
    return str(value or "").replace("\\", "\\\\").replace('"', '\\"')


def snort_endpoint(ip: str, port: Optional[int]) -> str:
    return f"{ip or 'any'} {port if port is not None else 'any'}"


def build_fallback_snort_rule(
    match: re.Match,
    src_ip: str,
    src_port: Optional[int],
    dst_ip: str,
    dst_port: Optional[int],
) -> str:
    protocol = str(match.group("protocol") or "ip").lower()
    msg = escape_snort_text(match.group("msg"))
    sid = match.group("sid")
    rev = match.group("rev")

    return (
        f'alert {protocol} '
        f'{snort_endpoint(src_ip, src_port)} -> {snort_endpoint(dst_ip, dst_port)} '
        f'(msg:"{msg}"; sid:{sid}; rev:{rev};)'
    )


def safe_yara_rule_name(value: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_]", "_", value or "").strip("_")

    if not name:
        name = "CTINK_YARA_UNMATCHED"

    if not re.match(r"^[A-Za-z_]", name):
        name = f"CTINK_{name}"

    return name


def build_fallback_yara_rule(rule_name: str) -> str:
    safe_name = safe_yara_rule_name(rule_name)
    return f"rule {safe_name} {{ condition: true }}"


def parse_snort_log_line(
    line: str,
    snort_rules: Dict[str, Dict[str, str]],
) -> Optional[Dict[str, Any]]:
    match = SNORT_LOG_RE.match(line.strip())

    if not match:
        return None

    sid = match.group("sid")
    rule_info = snort_rules.get(sid)

    if not rule_info and not SEND_UNMATCHED:
        return None

    src_ip, src_port = split_host_port(match.group("src"))
    dst_ip, dst_port = split_host_port(match.group("dst"))

    detected_at = parse_snort_time(match.group("ts"))
    action = rule_info.get("action") if rule_info else None

    rule_content = (
        rule_info.get("rule_content")
        if rule_info
        else build_fallback_snort_rule(match, src_ip, src_port, dst_ip, dst_port)
    )

    if not rule_content:
        rule_content = build_fallback_snort_rule(match, src_ip, src_port, dst_ip, dst_port)

    detail_obj = {
        "engine": "snort",
        "gid": match.group("gid"),
        "sid": sid,
        "rev": match.group("rev"),
        "message": match.group("msg"),
        "classification": match.group("classification"),
        "priority": int(match.group("priority")),
        "protocol": match.group("protocol"),
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "raw_log": line,
        "matched_rule": bool(rule_info),
    }

    return {
        "rule_content": rule_content,
        "detail": json.dumps(detail_obj, ensure_ascii=False),
        "result": snort_action_to_result(action),
        "detected_at": detected_at,
    }


def parse_yara_log_line(
    line: str,
    yara_rules: Dict[str, str],
) -> Optional[Dict[str, Any]]:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None

    if not isinstance(obj, dict):
        return None

    rule_name = str(obj.get("rule_name", "")).strip()

    if not rule_name:
        raw_output = str(obj.get("raw_output", "")).strip()
        if raw_output:
            rule_name = raw_output.split()[0]

    if not rule_name:
        return None

    rule_content = yara_rules.get(rule_name, "") or build_fallback_yara_rule(rule_name)

    if not rule_content and not SEND_UNMATCHED:
        return None

    detected_at = format_detected_at(obj.get("timestamp") or now_iso())

    detail_obj = {
        "engine": "yara",
        "rule_name": rule_name,
        "target_path": obj.get("target_path"),
        "raw_output": obj.get("raw_output"),
        "rule_file": obj.get("rule_file"),
        "scan_target": obj.get("scan_target"),
        "raw_log": line,
        "matched_rule": bool(yara_rules.get(rule_name, "")),
    }

    return {
        "rule_content": rule_content,
        "detail": json.dumps(detail_obj, ensure_ascii=False),
        "result": "DETECT",
        "detected_at": detected_at,
    }


class MqPublisher:
    def __init__(self) -> None:
        self.connection = None
        self.channel = None

    def connect(self) -> None:
        import pika

        if RABBITMQ_URL:
            params = pika.URLParameters(RABBITMQ_URL)
            params.heartbeat = RABBITMQ_HEARTBEAT
            params.blocked_connection_timeout = (
                RABBITMQ_BLOCKED_CONNECTION_TIMEOUT_SEC
            )
        else:
            credentials = pika.PlainCredentials(
                RABBITMQ_USERNAME,
                RABBITMQ_PASSWORD,
            )

            params = pika.ConnectionParameters(
                host=RABBITMQ_HOST,
                port=RABBITMQ_PORT,
                virtual_host=RABBITMQ_VHOST,
                credentials=credentials,
                heartbeat=RABBITMQ_HEARTBEAT,
                blocked_connection_timeout=(
                    RABBITMQ_BLOCKED_CONNECTION_TIMEOUT_SEC
                ),
            )

        self.connection = pika.BlockingConnection(params)
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue=IDS_LOG_OUTPUT_QUEUE, durable=True)

    def ensure_connected(self) -> None:
        if self.connection is None or self.connection.is_closed:
            self.connect()
            return

        if self.channel is None or self.channel.is_closed:
            self.connect()

    def publish(self, payload: Dict[str, Any]) -> None:
        import pika

        self.ensure_connected()

        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        self.channel.basic_publish(
            exchange="",
            routing_key=IDS_LOG_OUTPUT_QUEUE,
            properties=pika.BasicProperties(
                content_type="application/json",
                delivery_mode=2,
            ),
            body=body,
        )

    def close(self) -> None:
        try:
            if self.connection and self.connection.is_open:
                self.connection.close()
        except Exception:
            pass


def process_snort_logs(
    state: Dict[str, Any],
    publisher: MqPublisher,
    snort_rules: Dict[str, Dict[str, str]],
) -> None:
    lines = read_new_lines(SNORT_ALERT_FILE, state)

    for line in lines:
        payload = parse_snort_log_line(line, snort_rules)

        if not payload:
            continue

        event_dedupe_hash = build_event_dedupe_hash(payload)

        if was_sent_hash(state, "sent_event_hashes", event_dedupe_hash):
            print(
                json.dumps(
                    {
                        "status": "skipped_duplicate",
                        "engine": "snort",
                        "queue": IDS_LOG_OUTPUT_QUEUE,
                        "dedupe_hash": event_dedupe_hash,
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
            continue

        publisher.publish(payload)

        remember_sent_hash(state, "sent_event_hashes", event_dedupe_hash)
        save_state(state)

        print(
            json.dumps(
                {
                    "status": "published",
                    "engine": "snort",
                    "queue": IDS_LOG_OUTPUT_QUEUE,
                    "dedupe_hash": event_dedupe_hash,
                    "payload": payload,
                },
                ensure_ascii=False,
            ),
            flush=True,
        )


def process_yara_logs(
    state: Dict[str, Any],
    publisher: MqPublisher,
    yara_rules: Dict[str, str],
) -> None:
    lines = read_new_lines(YARA_LOG_FILE, state)

    for line in lines:
        payload = parse_yara_log_line(line, yara_rules)

        if not payload:
            continue

        event_dedupe_hash = build_event_dedupe_hash(payload)

        if was_sent_hash(state, "sent_event_hashes", event_dedupe_hash):
            print(
                json.dumps(
                    {
                        "status": "skipped_duplicate",
                        "engine": "yara",
                        "queue": IDS_LOG_OUTPUT_QUEUE,
                        "dedupe_hash": event_dedupe_hash,
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
            continue

        publisher.publish(payload)

        remember_sent_hash(state, "sent_event_hashes", event_dedupe_hash)
        save_state(state)

        print(
            json.dumps(
                {
                    "status": "published",
                    "engine": "yara",
                    "queue": IDS_LOG_OUTPUT_QUEUE,
                    "dedupe_hash": event_dedupe_hash,
                    "payload": payload,
                },
                ensure_ascii=False,
            ),
            flush=True,
        )


def main() -> None:
    try:
        import pika  # noqa: F401
    except ImportError:
        raise SystemExit("pika is not installed. Install with: pip install pika")

    validate_configuration()

    startup_info = {
        "status": "ids_log_forwarder_started",
        "snort_alert_file": SNORT_ALERT_FILE,
        "yara_log_file": YARA_LOG_FILE,
        "snort_rule_file": SNORT_RULE_FILE,
        "yara_rule_file": YARA_RULE_FILE,
        "output_queue": IDS_LOG_OUTPUT_QUEUE,
        "poll_interval_sec": POLL_INTERVAL_SEC,
        "error_retry_interval_sec": ERROR_RETRY_INTERVAL_SEC,
        "state_file": STATE_FILE,
    }
    startup_info.update(rabbitmq_public_config())

    print(
        json.dumps(startup_info, ensure_ascii=False),
        flush=True,
    )

    state = load_state()
    publisher = MqPublisher()

    while True:
        try:
            snort_rules = build_snort_rule_map()
            yara_rules = build_yara_rule_map()

            process_snort_logs(state, publisher, snort_rules)
            process_yara_logs(state, publisher, yara_rules)

            save_state(state)
            time.sleep(POLL_INTERVAL_SEC)

        except KeyboardInterrupt:
            break

        except Exception as exc:
            print(
                json.dumps(
                    {
                        "status": "forwarder_error",
                        "message": str(exc),
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )

            try:
                publisher.close()
            except Exception:
                pass

            time.sleep(ERROR_RETRY_INTERVAL_SEC)

    publisher.close()


if __name__ == "__main__":
    main()
