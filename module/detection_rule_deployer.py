# detection_rule_deployer.py
#
# Install:
#   sudo apt update
#   sudo apt install -y snort yara
#   pip install pika
#
# Run:
#   sudo python3 detection_rule_deployer.py apply --input apply.json
#   sudo python3 detection_rule_deployer.py remove --input remove.json
#   python3 detection_rule_deployer.py consume
#
# Env:
#   SNORT_CONF=/etc/snort/snort.conf
#   SNORT_DEFAULT_FILE=/etc/default/snort
#   SNORT_LOG_DIR=/var/log/snort
#   SNORT_SERVICE_NAME=snort
#   SNORT_DEFAULT_RULE_FILE=/etc/snort/rules/local.rules
#   YARA_DEFAULT_RULE_FILE=/opt/ctink/yara/rules/ctink_rules.yar
#   YARA_RULE_FILES_FILE=/etc/ctink/yara_rule_files.txt
#   YARA_RULE_DIRS_FILE=/etc/ctink/yara_rule_dirs.txt
#   YARA_TARGET_DIRS_FILE=/etc/ctink/yara_target_dirs.txt
#   YARA_DEFAULT_SCAN_TARGETS=/opt/ctink/yara/scan_target
#   YARA_SCANNER_SCRIPT=/usr/local/bin/ctink_yara_scanner.py
#   YARA_SCANNER_SERVICE=ctink-yara-scanner.service
#   YARA_SCAN_INTERVAL_SEC=30
#   YARA_LOG_FILE=/var/log/ctink/yara_scan.log
#   CTINK_DEPLOY_RELOAD=true
#   CTINK_BACKUP_DIR=/tmp/ctink_rule_backups
#   RABBITMQ_URL=amqp://guest:guest@localhost:5672/%2F
#   RULE_DEPLOY_APPLY_QUEUE=rule_deploy_apply
#   RULE_DEPLOY_REMOVE_QUEUE=rule_deploy_remove
#   DEPLOY_COMMAND_TIMEOUT=30

import os
import re
import sys
import json
import time
import shutil
import hashlib
import argparse
import tempfile
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set


SNORT_CONF = os.getenv("SNORT_CONF", "/etc/snort/snort.conf")
SNORT_DEFAULT_FILE = os.getenv("SNORT_DEFAULT_FILE", "/etc/default/snort")
SNORT_LOG_DIR = os.getenv("SNORT_LOG_DIR", "/var/log/snort")
SNORT_ALERT_FILE = os.path.join(SNORT_LOG_DIR, "alert")
SNORT_SERVICE_NAME = os.getenv("SNORT_SERVICE_NAME", "snort")
SNORT_DEFAULT_RULE_FILE = os.getenv("SNORT_DEFAULT_RULE_FILE", "/etc/snort/rules/local.rules")

YARA_DEFAULT_RULE_FILE = os.getenv("YARA_DEFAULT_RULE_FILE", "/opt/ctink/yara/rules/ctink_rules.yar")
YARA_RULE_FILES_FILE = os.getenv("YARA_RULE_FILES_FILE", "/etc/ctink/yara_rule_files.txt")
YARA_RULE_DIRS_FILE = os.getenv("YARA_RULE_DIRS_FILE", "/etc/ctink/yara_rule_dirs.txt")
YARA_TARGET_DIRS_FILE = os.getenv("YARA_TARGET_DIRS_FILE", "/etc/ctink/yara_target_dirs.txt")
YARA_DEFAULT_SCAN_TARGETS = os.getenv("YARA_DEFAULT_SCAN_TARGETS", "/opt/ctink/yara/scan_target")
YARA_SCANNER_SCRIPT = os.getenv("YARA_SCANNER_SCRIPT", "/usr/local/bin/ctink_yara_scanner.py")
YARA_SCANNER_SERVICE = os.getenv("YARA_SCANNER_SERVICE", "ctink-yara-scanner.service")
YARA_SCAN_INTERVAL_SEC = int(os.getenv("YARA_SCAN_INTERVAL_SEC", "30"))
YARA_LOG_FILE = os.getenv("YARA_LOG_FILE", "/var/log/ctink/yara_scan.log")

CTINK_DEPLOY_RELOAD = os.getenv("CTINK_DEPLOY_RELOAD", "true").lower() in {
    "1",
    "true",
    "yes",
    "y",
}

CTINK_BACKUP_DIR = os.getenv("CTINK_BACKUP_DIR", "/tmp/ctink_rule_backups")

RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/%2F")
RULE_DEPLOY_APPLY_QUEUE = os.getenv("RULE_DEPLOY_APPLY_QUEUE", "rule_deploy_apply")
RULE_DEPLOY_REMOVE_QUEUE = os.getenv("RULE_DEPLOY_REMOVE_QUEUE", "rule_deploy_remove")

COMMAND_TIMEOUT = int(os.getenv("DEPLOY_COMMAND_TIMEOUT", "30"))


def _run_command(cmd: List[str], timeout: int = COMMAND_TIMEOUT) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            timeout=timeout,
            capture_output=True,
            text=True,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout or "", exc.stderr or "command timeout"
    except Exception as exc:
        return 1, "", str(exc)


def _which(binary: str) -> Optional[str]:
    return shutil.which(binary)


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _path_needs_root(path: str) -> bool:
    return path.startswith(("/etc/", "/var/", "/opt/", "/usr/", "/lib/", "/run/"))


def _needs_root(rule_type: str, file_location: str) -> bool:
    if rule_type in {"snort", "yara"}:
        return True

    if CTINK_DEPLOY_RELOAD:
        return True

    if _path_needs_root(file_location):
        return True

    return False


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


def _ensure_parent_dir_and_file(path: str) -> bool:
    target = Path(path)
    changed = False

    if not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        changed = True

    if not target.exists():
        target.touch(exist_ok=True)
        changed = True

    return changed


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
        tmp_path = tmp.name

    os.replace(tmp_path, path)


def _write_text_if_changed(path: str, content: str) -> bool:
    current = _read_text(path)

    if current == content:
        return False

    _write_text_atomic(path, content)
    return True


def _chmod_if_needed(path: str, mode: int) -> None:
    try:
        current_mode = os.stat(path).st_mode & 0o777

        if current_mode != mode:
            os.chmod(path, mode)
    except Exception:
        pass


def _backup_file(path: str) -> Optional[str]:
    if not os.path.exists(path):
        return None

    Path(CTINK_BACKUP_DIR).mkdir(parents=True, exist_ok=True)

    digest = hashlib.sha256(os.path.abspath(path).encode()).hexdigest()[:12]
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


def _append_rollback_once(items: List[Tuple[str, Optional[str]]], path: str, backup_path: Optional[str]) -> None:
    for existing_path, _ in items:
        if existing_path == path:
            return

    items.append((path, backup_path))


def _rollback_files(items: List[Tuple[str, Optional[str]]]) -> None:
    for path, backup_path in reversed(items):
        _restore_backup(path, backup_path)


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


def _remove_wrapped_or_raw_rule(existing: str, rule_type: str, rule_content: str) -> Tuple[str, bool]:
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


def _normalize_abs_path(path: str) -> str:
    return os.path.realpath(os.path.abspath(path))


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


def _validate_input(input_json: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
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


def _ensure_root_for_operation(rule_type: str, file_location: str, action: str) -> Optional[Dict[str, Any]]:
    if _needs_root(rule_type, file_location) and not _is_root():
        message = (
            "root privileges required. "
            f"Run with sudo: sudo python3 detection_rule_deployer.py {action} --input <input.json>"
        )

        if action == "apply":
            return _json_apply_failure(message)

        return _json_remove_failure(message)

    return None


def _parse_snort_rule_path(snort_conf_content: str) -> Optional[str]:
    for line in snort_conf_content.splitlines():
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        match = re.match(r"^(?:var|ipvar)\s+RULE_PATH\s+(.+)$", stripped)
        if match:
            value = match.group(1).strip().strip('"').strip("'")
            return value

    return None


def _resolve_snort_include_path(include_value: str, rule_path: Optional[str]) -> str:
    include_value = include_value.strip().strip('"').strip("'")

    if rule_path:
        include_value = include_value.replace("$RULE_PATH", rule_path)
        include_value = include_value.replace("${RULE_PATH}", rule_path)

    if not os.path.isabs(include_value):
        conf_dir = os.path.dirname(_normalize_abs_path(SNORT_CONF))
        include_value = os.path.join(conf_dir, include_value)

    return _normalize_abs_path(include_value)


def _snort_included_paths(snort_conf_content: str) -> Set[str]:
    rule_path = _parse_snort_rule_path(snort_conf_content)
    included = set()

    for line in snort_conf_content.splitlines():
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        match = re.match(r"^include\s+(.+)$", stripped)
        if not match:
            continue

        include_value = match.group(1).strip()
        resolved = _resolve_snort_include_path(include_value, rule_path)
        included.add(resolved)

    return included


def _ensure_snort_rule_file_included(file_location: str) -> Tuple[bool, str, Optional[str], bool]:
    if not os.path.exists(SNORT_CONF):
        return False, f"snort.conf not found: {SNORT_CONF}", None, False

    _ensure_parent_dir_and_file(file_location)

    target_path = _normalize_abs_path(file_location)
    content = _read_text(SNORT_CONF)
    included_paths = _snort_included_paths(content)

    if target_path in included_paths:
        return True, "-", None, False

    backup_path = _backup_file(SNORT_CONF)

    try:
        if content and not content.endswith("\n"):
            content += "\n"

        content += "\n# CTINK include\n"
        content += f"include {target_path}\n"

        _write_text_atomic(SNORT_CONF, content)
        return True, "-", backup_path, True

    except Exception as exc:
        _restore_backup(SNORT_CONF, backup_path)
        return False, f"failed to include snort rule file in snort.conf: {exc}", None, False


def _ensure_snort_conf_alert_fast() -> Tuple[bool, str, Optional[str], bool]:
    if not os.path.exists(SNORT_CONF):
        return False, f"snort.conf not found: {SNORT_CONF}", None, False

    content = _read_text(SNORT_CONF)

    if "output alert_fast:" in content:
        return True, "-", None, False

    backup_path = _backup_file(SNORT_CONF)

    try:
        if content and not content.endswith("\n"):
            content += "\n"

        content += "\n# CTINK alert\n"
        content += "output alert_fast: alert\n"

        _write_text_atomic(SNORT_CONF, content)
        return True, "-", backup_path, True

    except Exception as exc:
        _restore_backup(SNORT_CONF, backup_path)
        return False, f"failed to update snort.conf for alert logging: {exc}", None, False


def _ensure_snort_default_alertmode() -> Tuple[bool, str, bool]:
    if not os.path.exists(SNORT_DEFAULT_FILE):
        return True, f"skipped because {SNORT_DEFAULT_FILE} does not exist", False

    content = _read_text(SNORT_DEFAULT_FILE)
    lines = content.splitlines()
    updated_lines = []
    found = False

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("ALERTMODE="):
            updated_lines.append("ALERTMODE=fast")
            found = True
        else:
            updated_lines.append(line)

    if not found:
        updated_lines.append("ALERTMODE=fast")

    new_content = "\n".join(updated_lines).strip() + "\n"

    if new_content == content:
        return True, "-", False

    backup_path = _backup_file(SNORT_DEFAULT_FILE)

    try:
        _write_text_atomic(SNORT_DEFAULT_FILE, new_content)
        return True, "-", True

    except Exception as exc:
        _restore_backup(SNORT_DEFAULT_FILE, backup_path)
        return False, f"failed to update {SNORT_DEFAULT_FILE}: {exc}", False


def _ensure_snort_alert_file_permission() -> Tuple[bool, str]:
    try:
        Path(SNORT_LOG_DIR).mkdir(parents=True, exist_ok=True)
        Path(SNORT_ALERT_FILE).touch(exist_ok=True)

        try:
            shutil.chown(SNORT_LOG_DIR, user="snort", group="adm")
        except Exception:
            pass

        try:
            shutil.chown(SNORT_ALERT_FILE, user="snort", group="adm")
        except Exception:
            pass

        _chmod_if_needed(SNORT_LOG_DIR, 0o2750)
        _chmod_if_needed(SNORT_ALERT_FILE, 0o640)

        return True, "-"

    except Exception as exc:
        return False, f"failed to prepare snort alert log file: {exc}"


def _ensure_snort_runtime_config(file_location: str) -> Tuple[bool, str, List[Tuple[str, Optional[str]]], bool]:
    conf_changes: List[Tuple[str, Optional[str]]] = []
    restart_needed = False

    ok, feedback, backup_path, changed = _ensure_snort_rule_file_included(file_location)
    if not ok:
        return False, feedback, conf_changes, restart_needed

    if changed:
        restart_needed = True
        _append_rollback_once(conf_changes, SNORT_CONF, backup_path)

    ok, feedback, backup_path, changed = _ensure_snort_conf_alert_fast()
    if not ok:
        _rollback_files(conf_changes)
        return False, feedback, [], restart_needed

    if changed:
        restart_needed = True
        _append_rollback_once(conf_changes, SNORT_CONF, backup_path)

    ok, feedback, changed = _ensure_snort_default_alertmode()
    if not ok:
        _rollback_files(conf_changes)
        return False, feedback, [], restart_needed

    if changed:
        restart_needed = True

    ok, feedback = _ensure_snort_alert_file_permission()
    if not ok:
        _rollback_files(conf_changes)
        return False, feedback, [], restart_needed

    return True, "-", conf_changes, restart_needed


def _check_snort_syntax_with_candidate(file_location: str, candidate_content: str) -> Tuple[bool, str]:
    snort_bin = _which("snort")

    if not snort_bin:
        return False, "snort command not found"

    _ensure_parent_dir_and_file(file_location)
    backup_path = _backup_file(file_location)

    try:
        _write_text_atomic(file_location, candidate_content)

        if os.path.exists(SNORT_CONF):
            cmd = [snort_bin, "-T", "-q", "-c", SNORT_CONF]
            code, stdout, stderr = _run_command(cmd)

            if code == 0:
                return True, "-"

            return False, (stderr or stdout).strip() or "snort syntax check failed"

        with tempfile.TemporaryDirectory(prefix="ctink_snort_conf_") as workdir:
            temp_conf = os.path.join(workdir, "snort_test.conf")
            conf_content = f"""
var HOME_NET any
var EXTERNAL_NET any
config classification: misc-activity,Misc activity,3
include {file_location}
"""
            _write_text_atomic(temp_conf, conf_content.strip() + "\n")

            cmd = [snort_bin, "-T", "-q", "-c", temp_conf]
            code, stdout, stderr = _run_command(cmd)

            if code == 0:
                return True, "-"

            return False, (stderr or stdout).strip() or "snort syntax check failed"

    finally:
        _restore_backup(file_location, backup_path)


def _check_yara_syntax_content(rule_content: str) -> Tuple[bool, str]:
    yara_bin = _which("yara")
    yarac_bin = _which("yarac")

    if not yara_bin and not yarac_bin:
        return False, "yara or yarac command not found"

    with tempfile.TemporaryDirectory(prefix="ctink_yara_syntax_") as workdir:
        rule_path = os.path.join(workdir, "rule.yar")
        empty_target = os.path.join(workdir, "empty.bin")
        compiled_path = os.path.join(workdir, "rule.compiled")

        _write_text_atomic(rule_path, rule_content.strip() + "\n")
        Path(empty_target).write_bytes(b"")

        if yarac_bin:
            cmd = [yarac_bin, rule_path, compiled_path]
            code, stdout, stderr = _run_command(cmd)

            if code == 0:
                return True, "-"

            return False, (stderr or stdout).strip() or "yarac syntax check failed"

        cmd = [yara_bin, rule_path, empty_target]
        code, stdout, stderr = _run_command(cmd)

        if code in {0, 1}:
            return True, "-"

        return False, (stderr or stdout).strip() or "yara syntax check failed"


def _read_lines_file(path: str) -> List[str]:
    content = _read_text(path)
    result = []

    for line in content.splitlines():
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        result.append(stripped)

    return result


def _write_unique_lines(path: str, values: List[str]) -> bool:
    seen = set()
    lines = []

    for value in values:
        normalized = _normalize_abs_path(value)

        if normalized in seen:
            continue

        seen.add(normalized)
        lines.append(normalized)

    new_content = "\n".join(lines).strip() + "\n"
    return _write_text_if_changed(path, new_content)


def _add_unique_line(path: str, value: str) -> bool:
    existing = _read_lines_file(path)
    before = set(_normalize_abs_path(x) for x in existing)
    normalized = _normalize_abs_path(value)

    if normalized in before:
        return False

    existing.append(value)
    return _write_unique_lines(path, existing)


def _default_yara_targets() -> List[str]:
    targets = []

    for item in YARA_DEFAULT_SCAN_TARGETS.split(","):
        stripped = item.strip()

        if stripped:
            targets.append(_normalize_abs_path(stripped))

    if not targets:
        targets.append(_normalize_abs_path("/opt/ctink/yara/scan_target"))

    return targets


def _ensure_yara_config_files(rule_file_location: str) -> Tuple[bool, bool]:
    changed = False
    rule_file = _normalize_abs_path(rule_file_location)
    rule_dir = _normalize_abs_path(str(Path(rule_file_location).parent))
    default_targets = _default_yara_targets()

    for path in [YARA_RULE_FILES_FILE, YARA_RULE_DIRS_FILE, YARA_TARGET_DIRS_FILE]:
        parent = Path(path).parent

        if not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)
            changed = True

    if not Path(rule_dir).exists():
        Path(rule_dir).mkdir(parents=True, exist_ok=True)
        changed = True

    for target in default_targets:
        if not Path(target).exists():
            Path(target).mkdir(parents=True, exist_ok=True)
            changed = True

    if _add_unique_line(YARA_RULE_FILES_FILE, rule_file):
        changed = True

    if _add_unique_line(YARA_RULE_DIRS_FILE, rule_dir):
        changed = True

    existing_targets = _read_lines_file(YARA_TARGET_DIRS_FILE)

    if not existing_targets:
        if _write_unique_lines(YARA_TARGET_DIRS_FILE, default_targets):
            changed = True
    else:
        merged = existing_targets + default_targets

        if _write_unique_lines(YARA_TARGET_DIRS_FILE, merged):
            changed = True

    return True, changed


def _scanner_script_content() -> str:
    return f'''#!/usr/bin/env python3
import os
import sys
import time
import subprocess
from pathlib import Path

RULE_FILES_FILE = "{YARA_RULE_FILES_FILE}"
RULE_DIRS_FILE = "{YARA_RULE_DIRS_FILE}"
TARGET_DIRS_FILE = "{YARA_TARGET_DIRS_FILE}"
LOG_FILE = "{YARA_LOG_FILE}"
INTERVAL = {YARA_SCAN_INTERVAL_SEC}

def read_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [x.strip() for x in f.read().splitlines() if x.strip() and not x.strip().startswith("#")]
    except FileNotFoundError:
        return []

def log(message):
    Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8", errors="ignore") as f:
        f.write(message.rstrip() + "\\n")

def collect_rule_files():
    result = []
    seen = set()

    for path in read_lines(RULE_FILES_FILE):
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            real = os.path.realpath(os.path.abspath(path))
            if real not in seen:
                seen.add(real)
                result.append(real)

    for rule_dir in read_lines(RULE_DIRS_FILE):
        if not os.path.isdir(rule_dir):
            continue

        for root, _, files in os.walk(rule_dir):
            for name in files:
                if name.startswith("."):
                    continue

                full = os.path.realpath(os.path.abspath(os.path.join(root, name)))

                if full in seen:
                    continue

                if not os.path.isfile(full) or os.path.getsize(full) == 0:
                    continue

                if not (name.endswith(".yar") or name.endswith(".yara") or name.endswith(".rules")):
                    continue

                seen.add(full)
                result.append(full)

    return result

def scan_once():
    rule_files = collect_rule_files()
    target_dirs = read_lines(TARGET_DIRS_FILE)

    if not rule_files:
        log("CTINK_YARA_NO_RULE_FILES")
        return

    if not target_dirs:
        log("CTINK_YARA_NO_TARGET_DIRS")
        return

    for rule_file in rule_files:
        for target_dir in target_dirs:
            if not os.path.exists(target_dir):
                continue

            cmd = ["yara", "-r", rule_file, target_dir]

            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                out = (proc.stdout or "").strip()
                err = (proc.stderr or "").strip()

                if out:
                    for line in out.splitlines():
                        log("CTINK_YARA_DETECT " + line)

                if err:
                    for line in err.splitlines():
                        log("CTINK_YARA_ERROR " + line)

            except Exception as exc:
                log("CTINK_YARA_EXCEPTION " + str(exc))

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        scan_once()
        return

    log("CTINK_YARA_SCANNER_START")
    while True:
        scan_once()
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
'''


def _ensure_yara_scanner_script() -> Tuple[bool, str, bool]:
    if not _which("yara"):
        return False, "yara command not found", False

    try:
        changed = False
        script_path = Path(YARA_SCANNER_SCRIPT)

        if not script_path.parent.exists():
            script_path.parent.mkdir(parents=True, exist_ok=True)
            changed = True

        if _write_text_if_changed(YARA_SCANNER_SCRIPT, _scanner_script_content()):
            changed = True

        if os.path.exists(YARA_SCANNER_SCRIPT):
            current_mode = os.stat(YARA_SCANNER_SCRIPT).st_mode & 0o777

            if current_mode != 0o755:
                os.chmod(YARA_SCANNER_SCRIPT, 0o755)
                changed = True

        log_path = Path(YARA_LOG_FILE)

        if not log_path.parent.exists():
            log_path.parent.mkdir(parents=True, exist_ok=True)
            changed = True

        if not log_path.exists():
            log_path.touch(exist_ok=True)
            changed = True

        current_log_mode = os.stat(YARA_LOG_FILE).st_mode & 0o777

        if current_log_mode != 0o640:
            os.chmod(YARA_LOG_FILE, 0o640)

        return True, "-", changed

    except Exception as exc:
        return False, f"failed to install yara scanner script: {exc}", False


def _yara_service_content() -> str:
    return f"""[Unit]
Description=CTINK YARA Scanner
After=network.target

[Service]
Type=simple
ExecStart={YARA_SCANNER_SCRIPT}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""


def _systemd_is_active(service_name: str) -> bool:
    code, _, _ = _run_command(["systemctl", "is-active", "--quiet", service_name])
    return code == 0


def _systemd_is_enabled(service_name: str) -> bool:
    code, _, _ = _run_command(["systemctl", "is-enabled", "--quiet", service_name])
    return code == 0


def _ensure_yara_systemd_service(script_changed: bool) -> Tuple[bool, str, bool]:
    service_path = f"/etc/systemd/system/{YARA_SCANNER_SERVICE}"
    service_content = _yara_service_content()
    service_changed = False
    restarted = False

    try:
        if _write_text_if_changed(service_path, service_content):
            service_changed = True

        if service_changed:
            code, stdout, stderr = _run_command(["systemctl", "daemon-reload"])

            if code != 0:
                return False, (stderr or stdout).strip() or "systemctl daemon-reload failed", restarted

        if not _systemd_is_enabled(YARA_SCANNER_SERVICE):
            code, stdout, stderr = _run_command(["systemctl", "enable", YARA_SCANNER_SERVICE])

            if code != 0:
                return False, (stderr or stdout).strip() or f"failed to enable {YARA_SCANNER_SERVICE}", restarted

        if service_changed or script_changed:
            code, stdout, stderr = _run_command(["systemctl", "restart", YARA_SCANNER_SERVICE])
            restarted = True

            if code != 0:
                return False, (stderr or stdout).strip() or f"failed to restart {YARA_SCANNER_SERVICE}", restarted

            return True, "-", restarted

        if not _systemd_is_active(YARA_SCANNER_SERVICE):
            code, stdout, stderr = _run_command(["systemctl", "start", YARA_SCANNER_SERVICE])
            restarted = True

            if code != 0:
                return False, (stderr or stdout).strip() or f"failed to start {YARA_SCANNER_SERVICE}", restarted

        return True, "-", restarted

    except Exception as exc:
        return False, f"failed to install yara systemd service: {exc}", restarted


def _run_yara_scan_once() -> Tuple[bool, str]:
    if not os.path.exists(YARA_SCANNER_SCRIPT):
        return False, f"yara scanner script not found: {YARA_SCANNER_SCRIPT}"

    code, stdout, stderr = _run_command([YARA_SCANNER_SCRIPT, "--once"], timeout=330)

    if code == 0:
        return True, "-"

    return False, (stderr or stdout).strip() or "yara scanner --once failed"


def _ensure_yara_runtime_config(rule_file_location: str) -> Tuple[bool, str, bool]:
    changed = False

    try:
        _, config_changed = _ensure_yara_config_files(rule_file_location)
        changed = changed or config_changed
    except Exception as exc:
        return False, f"failed to prepare yara scanner config: {exc}", changed

    ok, feedback, script_changed = _ensure_yara_scanner_script()

    if not ok:
        return False, feedback, changed

    changed = changed or script_changed

    if not CTINK_DEPLOY_RELOAD:
        return True, "yara scanner service skipped by CTINK_DEPLOY_RELOAD=false", changed

    if not _which("systemctl"):
        return False, "systemctl command not found", changed

    ok, feedback, service_changed = _ensure_yara_systemd_service(script_changed)

    if not ok:
        return False, feedback, changed

    changed = changed or service_changed

    return True, "-", changed


def _restart_service(service_name: str) -> Tuple[bool, str]:
    if not CTINK_DEPLOY_RELOAD:
        return True, "restart skipped by CTINK_DEPLOY_RELOAD=false"

    if not service_name:
        return True, "restart skipped because service name is empty"

    systemctl_bin = _which("systemctl")

    if not systemctl_bin:
        return False, "systemctl command not found"

    code, stdout, stderr = _run_command([systemctl_bin, "restart", service_name])

    if code == 0:
        return True, "-"

    return False, (stderr or stdout).strip() or f"failed to restart {service_name}"


def _ensure_service_running_or_restart(service_name: str, restart_needed: bool) -> Tuple[bool, str]:
    if not CTINK_DEPLOY_RELOAD:
        return True, "restart skipped by CTINK_DEPLOY_RELOAD=false"

    if not service_name:
        return True, "restart skipped because service name is empty"

    if not _which("systemctl"):
        return False, "systemctl command not found"

    if restart_needed:
        return _restart_service(service_name)

    if not _systemd_is_active(service_name):
        code, stdout, stderr = _run_command(["systemctl", "start", service_name])

        if code == 0:
            return True, "-"

        return False, (stderr or stdout).strip() or f"failed to start {service_name}"

    return True, "-"


def _apply_snort_rule(file_location: str, rule_content: str) -> Dict[str, Any]:
    ok, feedback, conf_changes, restart_needed = _ensure_snort_runtime_config(file_location)

    if not ok:
        return _json_apply_failure(feedback)

    current = _read_text(file_location)
    wrapped_rule = _wrap_rule("snort", rule_content)

    if rule_content.strip() in current or wrapped_rule.strip() in current:
        ok, feedback = _ensure_service_running_or_restart(SNORT_SERVICE_NAME, restart_needed)

        if not ok:
            return _json_apply_failure(feedback)

        return _json_success("success")

    candidate = current

    if candidate and not candidate.endswith("\n"):
        candidate += "\n"

    candidate += "\n" + wrapped_rule

    ok, feedback = _check_snort_syntax_with_candidate(file_location, candidate)

    if not ok:
        _rollback_files(conf_changes)
        return _json_apply_failure(feedback)

    backup_path = _backup_file(file_location)

    try:
        _write_text_atomic(file_location, candidate)

        ok, feedback = _ensure_service_running_or_restart(SNORT_SERVICE_NAME, True)

        if not ok:
            _restore_backup(file_location, backup_path)
            _rollback_files(conf_changes)
            _restart_service(SNORT_SERVICE_NAME)
            return _json_apply_failure(feedback)

        return _json_success("success")

    except Exception as exc:
        _restore_backup(file_location, backup_path)
        _rollback_files(conf_changes)
        return _json_apply_failure(str(exc))


def _apply_yara_rule(file_location: str, rule_content: str) -> Dict[str, Any]:
    ok, feedback = _check_yara_syntax_content(rule_content)

    if not ok:
        return _json_apply_failure(feedback)

    _ensure_parent_dir_and_file(file_location)

    current = _read_text(file_location)
    wrapped_rule = _wrap_rule("yara", rule_content)

    if rule_content.strip() in current or wrapped_rule.strip() in current:
        ok, feedback, _ = _ensure_yara_runtime_config(file_location)

        if not ok:
            return _json_apply_failure(feedback)

        _run_yara_scan_once()
        return _json_success("success")

    candidate = current

    if candidate and not candidate.endswith("\n"):
        candidate += "\n"

    candidate += "\n" + wrapped_rule

    backup_path = _backup_file(file_location)

    try:
        _write_text_atomic(file_location, candidate)

        ok, feedback, _ = _ensure_yara_runtime_config(file_location)

        if not ok:
            _restore_backup(file_location, backup_path)
            return _json_apply_failure(feedback)

        _run_yara_scan_once()
        return _json_success("success")

    except Exception as exc:
        _restore_backup(file_location, backup_path)
        return _json_apply_failure(str(exc))


def apply_detection_rule(input_json: Dict[str, Any]) -> Dict[str, Any]:
    validated, error = _validate_input(input_json)

    if error:
        return _json_apply_failure(error)

    rule_type = validated["rule_type"]
    file_location = validated["file_location"]
    rule_content = validated["rule_content"]

    root_error = _ensure_root_for_operation(rule_type, file_location, "apply")

    if root_error:
        return root_error

    if rule_type == "snort":
        return _apply_snort_rule(file_location, rule_content)

    if rule_type == "yara":
        return _apply_yara_rule(file_location, rule_content)

    return _json_apply_failure("unsupported rule_type")


def _remove_snort_rule(file_location: str, rule_content: str) -> Dict[str, Any]:
    ok, feedback, _, restart_needed = _ensure_snort_runtime_config(file_location)

    if not ok:
        return _json_remove_failure(feedback)

    current = _read_text(file_location)

    if not current:
        ok, feedback = _ensure_service_running_or_restart(SNORT_SERVICE_NAME, restart_needed)

        if not ok:
            return _json_remove_failure(feedback)

        return _json_success("removed")

    candidate, removed = _remove_wrapped_or_raw_rule(current, "snort", rule_content)

    if not removed:
        ok, feedback = _ensure_service_running_or_restart(SNORT_SERVICE_NAME, restart_needed)

        if not ok:
            return _json_remove_failure(feedback)

        return _json_success("removed")

    ok, feedback = _check_snort_syntax_with_candidate(file_location, candidate)

    if not ok:
        return _json_remove_failure(feedback)

    backup_path = _backup_file(file_location)

    try:
        _write_text_atomic(file_location, candidate)

        ok, feedback = _ensure_service_running_or_restart(SNORT_SERVICE_NAME, True)

        if not ok:
            _restore_backup(file_location, backup_path)
            _restart_service(SNORT_SERVICE_NAME)
            return _json_remove_failure(feedback)

        return _json_success("removed")

    except Exception as exc:
        _restore_backup(file_location, backup_path)
        return _json_remove_failure(str(exc))


def _remove_yara_rule(file_location: str, rule_content: str) -> Dict[str, Any]:
    if not os.path.exists(file_location):
        _ensure_parent_dir_and_file(file_location)

        ok, feedback, _ = _ensure_yara_runtime_config(file_location)

        if not ok:
            return _json_remove_failure(feedback)

        _run_yara_scan_once()
        return _json_success("removed")

    current = _read_text(file_location)

    if not current:
        ok, feedback, _ = _ensure_yara_runtime_config(file_location)

        if not ok:
            return _json_remove_failure(feedback)

        _run_yara_scan_once()
        return _json_success("removed")

    candidate, removed = _remove_wrapped_or_raw_rule(current, "yara", rule_content)

    if not removed:
        ok, feedback, _ = _ensure_yara_runtime_config(file_location)

        if not ok:
            return _json_remove_failure(feedback)

        _run_yara_scan_once()
        return _json_success("removed")

    if candidate.strip():
        ok, feedback = _check_yara_syntax_content(candidate)

        if not ok:
            return _json_remove_failure(feedback)

    backup_path = _backup_file(file_location)

    try:
        _write_text_atomic(file_location, candidate)

        ok, feedback, _ = _ensure_yara_runtime_config(file_location)

        if not ok:
            _restore_backup(file_location, backup_path)
            return _json_remove_failure(feedback)

        _run_yara_scan_once()
        return _json_success("removed")

    except Exception as exc:
        _restore_backup(file_location, backup_path)
        return _json_remove_failure(str(exc))


def remove_detection_rule(input_json: Dict[str, Any]) -> Dict[str, Any]:
    validated, error = _validate_input(input_json)

    if error:
        return _json_remove_failure(error)

    rule_type = validated["rule_type"]
    file_location = validated["file_location"]
    rule_content = validated["rule_content"]

    root_error = _ensure_root_for_operation(rule_type, file_location, "remove")

    if root_error:
        return root_error

    if rule_type == "snort":
        return _remove_snort_rule(file_location, rule_content)

    if rule_type == "yara":
        return _remove_yara_rule(file_location, rule_content)

    return _json_remove_failure("unsupported rule_type")


def _is_success_payload(payload: Dict[str, Any]) -> bool:
    return payload.get("status") in {"success", "removed"}


def _make_mq_response(payload: Dict[str, Any], error: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
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
            )
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

    channel.basic_consume(queue=RULE_DEPLOY_APPLY_QUEUE, on_message_callback=callback)
    channel.basic_consume(queue=RULE_DEPLOY_REMOVE_QUEUE, on_message_callback=callback)

    print(
        json.dumps(
            {
                "status": "worker_started",
                "apply_queue": RULE_DEPLOY_APPLY_QUEUE,
                "remove_queue": RULE_DEPLOY_REMOVE_QUEUE,
            },
            ensure_ascii=False,
        ),
        flush=True,
    )

    channel.start_consuming()


def _load_input_json(input_path: Optional[str], json_text: Optional[str]) -> Dict[str, Any]:
    if input_path:
        with open(input_path, "r", encoding="utf-8") as f:
            return json.load(f)

    if json_text:
        return json.loads(json_text)

    raise ValueError("Either --input or --json must be provided")


def main() -> None:
    parser = argparse.ArgumentParser(description="CTI-NK detection rule deployer")
    subparsers = parser.add_subparsers(dest="command", required=True)

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
