# detection_rule_deployer.py
#
# Purpose:
#   This module only inserts/removes Snort/YARA rules into shared rule files.
#   It does not run Snort, YARA, syntax checks, scanner setup, reload, restart, or systemctl.
#
# Install:
#   pip install pika
#
# Run:
#   sudo python3 detection_rule_deployer.py apply --input apply.json
#   sudo python3 detection_rule_deployer.py remove --input remove.json
#   python3 detection_rule_deployer.py consume
#
# Env (Defaults):
#   SNORT_DEFAULT_RULE_FILE=/shared/rules/snort/local.rules
#   YARA_DEFAULT_RULE_FILE=/shared/rules/yara/ctink_rules.yar
#   CTINK_BACKUP_DIR=/tmp/ctink_rule_backups
#   RABBITMQ_URL=amqp://guest:guest@localhost:5672/%2F
#   RULE_DEPLOY_APPLY_QUEUE=rule_deploy_apply
#   RULE_DEPLOY_REMOVE_QUEUE=rule_deploy_remove

import os
import re
import sys
import json
import time
import hashlib
import argparse
import tempfile
import shutil
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, List


SNORT_DEFAULT_RULE_FILE = os.getenv(
    "SNORT_DEFAULT_RULE_FILE",
    "/shared/rules/snort/local.rules",
)

YARA_DEFAULT_RULE_FILE = os.getenv(
    "YARA_DEFAULT_RULE_FILE",
    "/shared/rules/yara/ctink_rules.yar",
)

CTINK_BACKUP_DIR = os.getenv(
    "CTINK_BACKUP_DIR",
    "/tmp/ctink_rule_backups",
)

RABBITMQ_URL = os.getenv(
    "RABBITMQ_URL",
    "amqp://guest:guest@localhost:5672/%2F",
)

RULE_DEPLOY_APPLY_QUEUE = os.getenv(
    "RULE_DEPLOY_APPLY_QUEUE",
    "rule_deploy_apply",
)

RULE_DEPLOY_REMOVE_QUEUE = os.getenv(
    "RULE_DEPLOY_REMOVE_QUEUE",
    "rule_deploy_remove",
)


def _json_success(status: str) -> Dict[str, Any]:
    return {"status": status}


def _json_apply_failure(message: str) -> Dict[str, Any]:
    return {
        "status": "failed to apply",
        "message": message,
    }


def _json_remove_failure(message: str) -> Dict[str, Any]:
    return {
        "status": "failed to remove",
        "message": message,
    }


def _json_failure(message: str) -> Dict[str, Any]:
    return {
        "status": "failure",
        "message": message,
    }


def _read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def _ensure_parent_dir_and_file(path: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.touch(exist_ok=True)


def _write_text_atomic(path: str, content: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        delete=False,
        dir=str(target.parent),
    ) as tmp:
        tmp.write(content)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = tmp.name

    os.replace(tmp_path, path)


def _backup_file(path: str) -> Optional[str]:
    if not os.path.exists(path):
        return None

    Path(CTINK_BACKUP_DIR).mkdir(parents=True, exist_ok=True)

    digest = hashlib.sha256(os.path.abspath(path).encode("utf-8")).hexdigest()[:12]
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(
        CTINK_BACKUP_DIR,
        f"{Path(path).name}.{digest}.{timestamp}.bak",
    )

    shutil.copy2(path, backup_path)
    return backup_path


def _restore_backup(path: str, backup_path: Optional[str]) -> None:
    if backup_path and os.path.exists(backup_path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup_path, path)
        return

    if os.path.exists(path):
        os.remove(path)


def _normalize_abs_path(path: str) -> str:
    return os.path.realpath(os.path.abspath(path))


def _rule_hash(rule_content: str) -> str:
    return hashlib.sha256(rule_content.strip().encode("utf-8")).hexdigest()[:16]


def _comment_prefix(rule_type: str) -> str:
    if rule_type == "snort":
        return "#"

    if rule_type == "yara":
        return "//"

    return "#"


def _wrap_rule(rule_type: str, rule_content: str) -> str:
    prefix = _comment_prefix(rule_type)
    digest = _rule_hash(rule_content)

    return (
        f"{prefix} CTINK_RULE_BEGIN {digest}\n"
        f"{rule_content.strip()}\n"
        f"{prefix} CTINK_RULE_END {digest}\n"
    )


def _remove_wrapped_or_raw_rule(
    existing: str,
    rule_type: str,
    rule_content: str,
) -> Tuple[str, bool]:
    digest = _rule_hash(rule_content)
    prefix = _comment_prefix(rule_type)

    begin = f"{prefix} CTINK_RULE_BEGIN {digest}"
    end = f"{prefix} CTINK_RULE_END {digest}"

    begin_idx = existing.find(begin)

    if begin_idx != -1:
        end_idx = existing.find(end, begin_idx)

        if end_idx != -1:
            end_idx += len(end)

            while end_idx < len(existing) and existing[end_idx] in "\r\n":
                end_idx += 1

            new_content = existing[:begin_idx] + existing[end_idx:]
            return new_content, True

    raw = rule_content.strip()

    if raw and raw in existing:
        new_content = existing.replace(raw, "", 1)
        return new_content, True

    return existing, False


def _infer_rule_type(input_json: Dict[str, Any]) -> Optional[str]:
    rule_type = input_json.get("rule_type")

    if isinstance(rule_type, str):
        normalized = rule_type.strip().lower()

        if normalized in {"snort", "yara"}:
            return normalized

    file_location = str(input_json.get("file_location", "")).lower()
    rule_content = str(input_json.get("rule_content", "")).strip().lower()

    if file_location.endswith((".yar", ".yara")):
        return "yara"

    if "yara" in file_location:
        return "yara"

    if "snort" in file_location or file_location.endswith((".rules", ".rule")):
        return "snort"

    snort_actions = (
        "alert ",
        "log ",
        "pass ",
        "activate ",
        "dynamic ",
        "drop ",
        "reject ",
        "sdrop ",
    )

    if rule_content.startswith(snort_actions):
        return "snort"

    if rule_content.startswith("rule ") or "\nrule " in rule_content:
        return "yara"

    return None


def _default_file_location(rule_type: str) -> str:
    if rule_type == "snort":
        return SNORT_DEFAULT_RULE_FILE

    if rule_type == "yara":
        return YARA_DEFAULT_RULE_FILE

    return ""


def _validate_input(
    input_json: Dict[str, Any],
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if not isinstance(input_json, dict):
        return None, "input must be a JSON object"

    rule_content = input_json.get("rule_content")

    if not isinstance(rule_content, str) or not rule_content.strip():
        return None, "rule_content must be a non-empty string"

    rule_type = _infer_rule_type(input_json)

    if rule_type not in {"snort", "yara"}:
        return None, "rule_type cannot be inferred. Add rule_type as 'snort' or 'yara'"

    file_location = input_json.get("file_location")

    if file_location is None or str(file_location).strip() == "":
        file_location = _default_file_location(rule_type)

    if not isinstance(file_location, str) or not file_location.strip():
        return None, "file_location must be a non-empty string"

    return {
        "rule_type": rule_type,
        "file_location": _normalize_abs_path(file_location.strip()),
        "rule_content": rule_content.strip(),
    }, None


class _FileLock:
    def __init__(self, target_path: str):
        self.target_path = target_path
        self.lock_path = f"{target_path}.lock"
        self.fd = None

    def __enter__(self):
        Path(self.lock_path).parent.mkdir(parents=True, exist_ok=True)
        self.fd = open(self.lock_path, "w", encoding="utf-8")

        try:
            import fcntl

            fcntl.flock(self.fd.fileno(), fcntl.LOCK_EX)
        except ImportError:
            pass

        return self

    def __exit__(self, exc_type, exc, tb):
        if self.fd:
            try:
                import fcntl

                fcntl.flock(self.fd.fileno(), fcntl.LOCK_UN)
            except ImportError:
                pass

            self.fd.close()


def _is_rule_already_present(
    current: str,
    rule_type: str,
    rule_content: str,
) -> bool:
    wrapped_rule = _wrap_rule(rule_type, rule_content)

    if wrapped_rule.strip() in current:
        return True

    digest = _rule_hash(rule_content)
    prefix = _comment_prefix(rule_type)
    begin = f"{prefix} CTINK_RULE_BEGIN {digest}"

    if begin in current:
        return True

    if rule_content.strip() in current:
        return True

    return False


def _append_rule_to_file(
    rule_type: str,
    file_location: str,
    rule_content: str,
) -> Dict[str, Any]:
    _ensure_parent_dir_and_file(file_location)

    with _FileLock(file_location):
        current = _read_text(file_location)

        if _is_rule_already_present(current, rule_type, rule_content):
            return _json_success("success")

        wrapped_rule = _wrap_rule(rule_type, rule_content)

        candidate = current

        if candidate and not candidate.endswith("\n"):
            candidate += "\n"

        candidate += "\n" + wrapped_rule

        backup_path = _backup_file(file_location)

        try:
            _write_text_atomic(file_location, candidate)
            return _json_success("success")
        except Exception as exc:
            _restore_backup(file_location, backup_path)
            return _json_apply_failure(str(exc))


def _remove_rule_from_file(
    rule_type: str,
    file_location: str,
    rule_content: str,
) -> Dict[str, Any]:
    _ensure_parent_dir_and_file(file_location)

    with _FileLock(file_location):
        current = _read_text(file_location)

        if not current:
            return _json_success("removed")

        candidate, removed = _remove_wrapped_or_raw_rule(
            current,
            rule_type,
            rule_content,
        )

        if not removed:
            return _json_success("removed")

        backup_path = _backup_file(file_location)

        try:
            _write_text_atomic(file_location, candidate)
            return _json_success("removed")
        except Exception as exc:
            _restore_backup(file_location, backup_path)
            return _json_remove_failure(str(exc))


def _apply_snort_rule(file_location: str, rule_content: str) -> Dict[str, Any]:
    return _append_rule_to_file("snort", file_location, rule_content)


def _apply_yara_rule(file_location: str, rule_content: str) -> Dict[str, Any]:
    return _append_rule_to_file("yara", file_location, rule_content)


def apply_detection_rule(input_json: Dict[str, Any]) -> Dict[str, Any]:
    validated, error = _validate_input(input_json)

    if error:
        return _json_apply_failure(error)

    rule_type = validated["rule_type"]
    file_location = validated["file_location"]
    rule_content = validated["rule_content"]

    if rule_type == "snort":
        return _apply_snort_rule(file_location, rule_content)

    if rule_type == "yara":
        return _apply_yara_rule(file_location, rule_content)

    return _json_apply_failure("unsupported rule_type")


def _remove_snort_rule(file_location: str, rule_content: str) -> Dict[str, Any]:
    return _remove_rule_from_file("snort", file_location, rule_content)


def _remove_yara_rule(file_location: str, rule_content: str) -> Dict[str, Any]:
    return _remove_rule_from_file("yara", file_location, rule_content)


def remove_detection_rule(input_json: Dict[str, Any]) -> Dict[str, Any]:
    validated, error = _validate_input(input_json)

    if error:
        return _json_remove_failure(error)

    rule_type = validated["rule_type"]
    file_location = validated["file_location"]
    rule_content = validated["rule_content"]

    if rule_type == "snort":
        return _remove_snort_rule(file_location, rule_content)

    if rule_type == "yara":
        return _remove_yara_rule(file_location, rule_content)

    return _json_remove_failure("unsupported rule_type")


def _is_success_payload(payload: Dict[str, Any]) -> bool:
    return payload.get("status") in {"success", "removed"}


def _make_mq_response(
    payload: Dict[str, Any],
    error: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    if error:
        return {
            "message_type": "rule_deploy_response",
            "status": "error",
            "payload": None,
            "error": error,
        }

    success_status = _is_success_payload(payload)

    return {
        "message_type": "rule_deploy_response",
        "status": "success" if success_status else "error",
        "payload": payload,
        "error": None if success_status else {
            "code": "deploy_failed",
            "message": str(payload.get("message", "deployment failed")),
        },
    }


def handle_mq_message(action: str, message_json: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(message_json, dict):
        return _make_mq_response(
            {},
            {
                "code": "invalid_message",
                "message": "message must be a JSON object",
            },
        )

    payload = message_json.get("payload", message_json)

    if not isinstance(payload, dict):
        return _make_mq_response(
            {},
            {
                "code": "invalid_payload",
                "message": "payload must be a JSON object",
            },
        )

    if action == "apply":
        result = apply_detection_rule(payload)
        return _make_mq_response(result)

    if action in {"remove", "delete"}:
        result = remove_detection_rule(payload)
        return _make_mq_response(result)

    return _make_mq_response(
        {},
        {
            "code": "invalid_action",
            "message": "action must be apply or remove",
        },
    )


def consume_mq() -> None:
    try:
        import pika
    except ImportError:
        print(
            json.dumps(
                _json_failure("pika is not installed. Install with: pip install pika"),
                ensure_ascii=False,
            ),
            flush=True,
        )
        sys.exit(1)

    params = pika.URLParameters(RABBITMQ_URL)
    connection = pika.BlockingConnection(params)
    channel = connection.channel()

    channel.queue_declare(queue=RULE_DEPLOY_APPLY_QUEUE, durable=True)
    channel.queue_declare(queue=RULE_DEPLOY_REMOVE_QUEUE, durable=True)
    channel.basic_qos(prefetch_count=1)

    def callback(ch, method, properties, body):
        queue_name = method.routing_key
        action = "apply" if queue_name == RULE_DEPLOY_APPLY_QUEUE else "remove"

        try:
            message_json = json.loads(body.decode("utf-8"))
            response = handle_mq_message(action, message_json)
        except Exception as exc:
            response = _make_mq_response(
                {},
                {
                    "code": "worker_exception",
                    "message": str(exc),
                },
            )

        response_body = json.dumps(response, ensure_ascii=False).encode("utf-8")

        if properties.reply_to:
            ch.basic_publish(
                exchange="",
                routing_key=properties.reply_to,
                properties=pika.BasicProperties(
                    correlation_id=properties.correlation_id,
                    content_type="application/json",
                    delivery_mode=2,
                ),
                body=response_body,
            )
        else:
            print(response_body.decode("utf-8"), flush=True)

        ch.basic_ack(delivery_tag=method.delivery_tag)

    channel.basic_consume(
        queue=RULE_DEPLOY_APPLY_QUEUE,
        on_message_callback=callback,
    )

    channel.basic_consume(
        queue=RULE_DEPLOY_REMOVE_QUEUE,
        on_message_callback=callback,
    )

    print(
        json.dumps(
            {
                "status": "worker_started",
                "apply_queue": RULE_DEPLOY_APPLY_QUEUE,
                "remove_queue": RULE_DEPLOY_REMOVE_QUEUE,
                "snort_default_rule_file": SNORT_DEFAULT_RULE_FILE,
                "yara_default_rule_file": YARA_DEFAULT_RULE_FILE,
            },
            ensure_ascii=False,
        ),
        flush=True,
    )

    channel.start_consuming()


def _load_input_json(
    input_path: Optional[str],
    json_text: Optional[str],
) -> Dict[str, Any]:
    if input_path:
        with open(input_path, "r", encoding="utf-8") as f:
            return json.load(f)

    if json_text:
        return json.loads(json_text)

    raise ValueError("Either --input or --json must be provided")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CTI-NK shared rule file writer",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("--input", help="input JSON file path")
    apply_parser.add_argument("--json", help="input JSON string")

    remove_parser = subparsers.add_parser("remove")
    remove_parser.add_argument("--input", help="input JSON file path")
    remove_parser.add_argument("--json", help="input JSON string")

    subparsers.add_parser("consume")

    args = parser.parse_args()

    if args.command == "consume":
        consume_mq()
        return

    try:
        input_json = _load_input_json(args.input, args.json)

        if args.command == "apply":
            result = apply_detection_rule(input_json)
        elif args.command == "remove":
            result = remove_detection_rule(input_json)
        else:
            result = _json_failure("unknown command")

    except Exception as exc:
        if args.command == "apply":
            result = _json_apply_failure(str(exc))
        elif args.command == "remove":
            result = _json_remove_failure(str(exc))
        else:
            result = _json_failure(str(exc))

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
