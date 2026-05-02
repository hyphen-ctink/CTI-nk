# detection_rule_validator.py
#
# 리눅스 기준 설치 예:
#   sudo apt update
#   sudo apt install -y snort yara p7zip-full
#   pip install scapy
#
# 환경변수 설정:
#   export MALWAREBAZAAR_AUTH_KEY="발급받은_Auth_Key"
#
# 선택 환경변수 설정:
#   export SNORT_CONF="/etc/snort/snort.conf"
#   export NORMAL_SNORT_DIR="/tmp/normal/snort"
#   export NORMAL_YARA_DIR="/tmp/normal/yara"
#   export MALWARE_SAMPLE_DIR="/tmp/ctink_malware_samples"
#
# 정상 데이터셋 경로:
#   /tmp/normal/snort/ip.txt
#   /tmp/normal/snort/domain.txt
#   /tmp/normal/snort/url.txt
#   /tmp/normal/yara/
#
# 일반 테스트:
#   python3 detection_rule_validator.py
#
# LangGraph 일반 호출:
#   from detection_rule_validator import validate_detection_rule
#   result = validate_detection_rule({
#       "rule_type": "snort",
#       "ioc_list": [
#           {"ioc_type": "ip", "ioc_value": "192.168.1.1"}
#       ],
#       "rule_content": "alert icmp 192.168.1.1 any -> any any (msg:\"test\"; sid:1000001; rev:1;)"
#   })
#
# LangGraph MQ JSON 호출:
#   from detection_rule_validator import validate_detection_rule_mq_json
#   result = validate_detection_rule_mq_json({
#       "message_type": "rule_validation_request",
#       "payload": {
#           "rule_type": "snort",
#           "ioc_list": [
#               {"ioc_type": "ip", "ioc_value": "192.168.1.1"}
#           ],
#           "rule_content": "alert icmp 192.168.1.1 any -> any any (msg:\"test\"; sid:1000001; rev:1;)"
#       }
#   })

import os
import re
import json
import shutil
import tempfile
import hashlib
import urllib.parse
import urllib.request
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


SNORT_IOC_TYPES = {"ip", "domain", "url"}
YARA_IOC_TYPES = {"hash"}

NORMAL_SNORT_DIR = os.getenv("NORMAL_SNORT_DIR", "/tmp/normal/snort")
NORMAL_YARA_DIR = os.getenv("NORMAL_YARA_DIR", "/tmp/normal/yara")
MALWARE_SAMPLE_DIR = os.getenv("MALWARE_SAMPLE_DIR", "/tmp/ctink_malware_samples")

MALWAREBAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1/"
MALWAREBAZAAR_AUTH_KEY_ENV = "MALWAREBAZAAR_AUTH_KEY"
MALWARE_ZIP_PASSWORD = os.getenv("MALWARE_ZIP_PASSWORD", "infected")

COMMAND_TIMEOUT = int(os.getenv("VALIDATION_COMMAND_TIMEOUT", "20"))
MALWAREBAZAAR_TIMEOUT = int(os.getenv("MALWAREBAZAAR_TIMEOUT", "60"))


def _get_malwarebazaar_headers() -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    auth_key = os.getenv(MALWAREBAZAAR_AUTH_KEY_ENV)

    if not auth_key:
        return None, (
            "MALWAREBAZAAR_AUTH_KEY is missing. "
            "Set it with: export MALWAREBAZAAR_AUTH_KEY='your_auth_key'"
        )

    return {
        "User-Agent": "ctink-validator",
        "Content-Type": "application/x-www-form-urlencoded",
        "Auth-Key": auth_key,
    }, None


def _is_hash_not_found_status(status: Any) -> bool:
    if not isinstance(status, str):
        return False

    normalized = status.strip().lower()

    return normalized in {
        "hash_not_found",
        "file_not_found",
        "not_found",
        "no_results",
        "no_result",
        "not_found_or_no_api_access",
    } or "not_found" in normalized


def _is_hash_not_found_feedback(feedback: str) -> bool:
    normalized = feedback.strip().lower()

    return (
        "hash not found in web" in normalized
        or "hash_not_found" in normalized
        or "file_not_found" in normalized
        or "not_found" in normalized
        or "no_results" in normalized
        or "no result" in normalized
    )


def _run_command(
    cmd: List[str],
    timeout: int = COMMAND_TIMEOUT,
    cwd: Optional[str] = None,
) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
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


def _write_text(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def _read_lines(path: str, limit: int = 100) -> List[str]:
    if not os.path.exists(path):
        return []

    result = []

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            value = line.strip()

            if not value or value.startswith("#"):
                continue

            result.append(value)

            if len(result) >= limit:
                break

    return result


def _safe_result(
    grammar_result: str,
    grammar_feedback: str,
    fn_result: str,
    fn_feedback: str,
    fp_result: str,
    fp_feedback: str,
) -> Dict[str, str]:
    return {
        "grammar_result": grammar_result,
        "grammar_feedback": grammar_feedback,
        "fn_result": fn_result,
        "fn_feedback": fn_feedback,
        "fp_result": fp_result,
        "fp_feedback": fp_feedback,
    }


def _validate_input(input_json: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if not isinstance(input_json, dict):
        return None, "input must be dict"

    rule_type = input_json.get("rule_type")
    ioc_list = input_json.get("ioc_list")
    rule_content = input_json.get("rule_content")

    if rule_type not in {"snort", "yara"}:
        return None, "rule_type must be 'snort' or 'yara'"

    if not isinstance(ioc_list, list) or not ioc_list:
        return None, "ioc_list must be non-empty list"

    if not isinstance(rule_content, str) or not rule_content.strip():
        return None, "rule_content must be non-empty string"

    normalized_iocs = []

    for item in ioc_list:
        if not isinstance(item, dict):
            return None, "each ioc item must be dict"

        ioc_type = item.get("ioc_type")
        ioc_value = item.get("ioc_value")

        if not isinstance(ioc_type, str) or not isinstance(ioc_value, str):
            return None, "ioc_type and ioc_value must be string"

        ioc_type = ioc_type.strip().lower()
        ioc_value = ioc_value.strip()

        if rule_type == "snort" and ioc_type not in SNORT_IOC_TYPES:
            return None, "snort ioc_type must be ip, domain, or url"

        if rule_type == "yara" and ioc_type not in YARA_IOC_TYPES:
            return None, "yara ioc_type must be hash"

        normalized_iocs.append(
            {
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
            }
        )

    if rule_type == "yara" and len(normalized_iocs) != 1:
        return None, "yara validation expects exactly one hash IoC"

    return {
        "rule_type": rule_type,
        "ioc_list": normalized_iocs,
        "rule_content": rule_content.strip(),
    }, None


def _simple_snort_rule_structure_check(rule_content: str) -> Tuple[bool, str]:
    stripped = rule_content.strip()

    if not re.match(r"^(alert|log|pass|activate|dynamic|drop|reject|sdrop)\s+", stripped):
        return False, "snort rule action is missing or invalid"

    if "(" not in stripped or ")" not in stripped:
        return False, "snort rule option parentheses are missing"

    if "sid:" not in stripped:
        return False, "snort rule sid option is missing"

    if not stripped.endswith(")"):
        return False, "snort rule must end with ')'"

    return True, "-"


def _make_snort_conf(rule_path: str, workdir: str, prefer_base_conf: bool = True) -> str:
    conf_path = os.path.join(workdir, "snort_test.conf")
    base_conf = os.getenv("SNORT_CONF", "/etc/snort/snort.conf")

    if prefer_base_conf and os.path.exists(base_conf):
        content = f"""
include {base_conf}
include {rule_path}
"""
    else:
        content = f"""
var HOME_NET any
var EXTERNAL_NET any
var RULE_PATH {workdir}
config classification: misc-activity,Misc activity,3
include {rule_path}
"""

    _write_text(conf_path, content.strip() + "\n")
    return conf_path


def _snort_grammar_check(rule_content: str) -> Tuple[str, str]:
    ok, feedback = _simple_snort_rule_structure_check(rule_content)
    if not ok:
        return "fail", feedback

    snort_bin = _which("snort")
    if not snort_bin:
        return "fail", "snort command not found"

    with tempfile.TemporaryDirectory(prefix="ctink_snort_grammar_") as workdir:
        rule_path = os.path.join(workdir, "local.rules")
        _write_text(rule_path, rule_content + "\n")

        last_feedback = ""

        for prefer_base in (True, False):
            conf_path = _make_snort_conf(rule_path, workdir, prefer_base_conf=prefer_base)
            cmd = [snort_bin, "-T", "-q", "-c", conf_path]
            code, stdout, stderr = _run_command(cmd, timeout=COMMAND_TIMEOUT)

            if code == 0:
                return "success", "-"

            last_feedback = (stderr or stdout).strip()

        return "fail", last_feedback or "snort grammar check failed"


def _yara_grammar_check(rule_content: str) -> Tuple[str, str]:
    yara_bin = _which("yara")
    if not yara_bin:
        return "fail", "yara command not found"

    with tempfile.TemporaryDirectory(prefix="ctink_yara_grammar_") as workdir:
        rule_path = os.path.join(workdir, "rule.yar")
        target_path = os.path.join(workdir, "empty_target.bin")

        _write_text(rule_path, rule_content + "\n")
        Path(target_path).write_bytes(b"")

        cmd = [yara_bin, rule_path, target_path]
        code, stdout, stderr = _run_command(cmd, timeout=COMMAND_TIMEOUT)

        if code in (0, 1):
            return "success", "-"

        return "fail", (stderr or stdout).strip() or "yara grammar check failed"


def _import_scapy():
    try:
        from scapy.all import Ether, IP, ICMP, TCP, Raw, wrpcap
        return Ether, IP, ICMP, TCP, Raw, wrpcap, None
    except Exception as exc:
        return None, None, None, None, None, None, str(exc)


def _http_payload_for_ioc(ioc_type: str, ioc_value: str) -> bytes:
    if ioc_type == "domain":
        host = ioc_value
        request_target = "/"

    elif ioc_type == "url":
        parsed = urllib.parse.urlparse(ioc_value if "://" in ioc_value else "http://" + ioc_value)
        host = parsed.netloc or parsed.path.split("/")[0]
        path = parsed.path or "/"

        if parsed.query:
            path += "?" + parsed.query

        request_target = ioc_value

    else:
        host = "localhost"
        request_target = "/"

    payload = (
        f"GET {request_target} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: ctink-validator\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )

    return payload.encode("utf-8", errors="ignore")


def _make_snort_attack_pcap(ioc_type: str, ioc_value: str, pcap_path: str) -> Optional[str]:
    Ether, IP, ICMP, TCP, Raw, wrpcap, err = _import_scapy()

    if err:
        return f"scapy import failed: {err}"

    packets = []

    if ioc_type == "ip":
        packets.append(
            Ether()
            / IP(src=ioc_value, dst="127.0.0.1")
            / ICMP()
        )
        packets.append(
            Ether()
            / IP(src=ioc_value, dst="127.0.0.1")
            / TCP(sport=44444, dport=80, flags="S", seq=1)
        )

    elif ioc_type in {"domain", "url"}:
        payload = _http_payload_for_ioc(ioc_type, ioc_value)
        packets.append(
            Ether()
            / IP(src="10.10.10.10", dst="127.0.0.1")
            / TCP(sport=44444, dport=80, flags="PA", seq=1, ack=1)
            / Raw(load=payload)
        )

    else:
        return f"unsupported snort ioc_type: {ioc_type}"

    wrpcap(pcap_path, packets)
    return None


def _make_snort_normal_pcap(ioc_type: str, normal_value: str, pcap_path: str) -> Optional[str]:
    Ether, IP, ICMP, TCP, Raw, wrpcap, err = _import_scapy()

    if err:
        return f"scapy import failed: {err}"

    packets = []

    if ioc_type == "ip":
        packets.append(
            Ether()
            / IP(src=normal_value, dst="127.0.0.1")
            / ICMP()
        )

    elif ioc_type in {"domain", "url"}:
        payload = _http_payload_for_ioc(ioc_type, normal_value)
        packets.append(
            Ether()
            / IP(src="10.20.30.40", dst="127.0.0.1")
            / TCP(sport=45454, dport=80, flags="PA", seq=1, ack=1)
            / Raw(load=payload)
        )

    else:
        return f"unsupported snort ioc_type: {ioc_type}"

    wrpcap(pcap_path, packets)
    return None


def _run_snort_pcap(rule_content: str, pcap_path: str) -> Tuple[bool, str]:
    snort_bin = _which("snort")
    if not snort_bin:
        return False, "snort command not found"

    with tempfile.TemporaryDirectory(prefix="ctink_snort_run_") as workdir:
        rule_path = os.path.join(workdir, "local.rules")
        logdir = os.path.join(workdir, "logs")
        os.makedirs(logdir, exist_ok=True)

        _write_text(rule_path, rule_content + "\n")

        last_feedback = ""

        for prefer_base in (True, False):
            conf_path = _make_snort_conf(rule_path, workdir, prefer_base_conf=prefer_base)
            cmd = [
                snort_bin,
                "-q",
                "-A",
                "fast",
                "-c",
                conf_path,
                "-r",
                pcap_path,
                "-l",
                logdir,
            ]

            code, stdout, stderr = _run_command(cmd, timeout=COMMAND_TIMEOUT)
            alert_text = _read_text(os.path.join(logdir, "alert"))

            if code == 0:
                if alert_text.strip():
                    return True, alert_text.strip()

                return False, "no snort alert"

            last_feedback = (stderr or stdout or alert_text).strip()

        return False, last_feedback or "snort pcap run failed"


def _snort_fn_check(rule_content: str, ioc_list: List[Dict[str, str]]) -> Tuple[str, str]:
    failed = []
    passed = []

    with tempfile.TemporaryDirectory(prefix="ctink_snort_fn_") as workdir:
        for ioc in ioc_list:
            ioc_type = ioc["ioc_type"]
            ioc_value = ioc["ioc_value"]
            pcap_path = os.path.join(workdir, f"attack_{ioc_type}_{len(passed) + len(failed)}.pcap")

            err = _make_snort_attack_pcap(ioc_type, ioc_value, pcap_path)

            if err:
                failed.append(f"{ioc_type}:{ioc_value} ({err})")
                continue

            alerted, feedback = _run_snort_pcap(rule_content, pcap_path)

            if alerted:
                passed.append(f"{ioc_type}:{ioc_value}")
            else:
                failed.append(f"{ioc_type}:{ioc_value} ({feedback})")

    if failed:
        return "fail", "failed attack data: " + ", ".join(failed)

    return "success", "-"


def _snort_fp_check(rule_content: str, ioc_list: List[Dict[str, str]]) -> Tuple[str, str]:
    failed = []

    with tempfile.TemporaryDirectory(prefix="ctink_snort_fp_") as workdir:
        for ioc in ioc_list:
            ioc_type = ioc["ioc_type"]
            normal_file = os.path.join(NORMAL_SNORT_DIR, f"{ioc_type}.txt")
            normal_values = _read_lines(normal_file, limit=100)

            if not normal_values:
                return "fail", f"normal dataset not found or empty: {normal_file}"

            for idx, normal_value in enumerate(normal_values):
                pcap_path = os.path.join(workdir, f"normal_{ioc_type}_{idx}.pcap")

                err = _make_snort_normal_pcap(ioc_type, normal_value, pcap_path)

                if err:
                    failed.append(f"{ioc_type}:{normal_value} ({err})")
                    continue

                alerted, feedback = _run_snort_pcap(rule_content, pcap_path)

                if alerted:
                    failed.append(f"{ioc_type}:{normal_value} (false positive)")
                    break

    if failed:
        return "fail", "failed normal data: " + ", ".join(failed)

    return "success", "-"


def _query_malwarebazaar_hash(file_hash: str) -> Tuple[bool, Optional[str], str]:
    headers, header_error = _get_malwarebazaar_headers()

    if header_error:
        return False, None, header_error

    data = urllib.parse.urlencode(
        {
            "query": "get_info",
            "hash": file_hash,
        }
    ).encode()

    req = urllib.request.Request(
        MALWAREBAZAAR_API_URL,
        data=data,
        method="POST",
        headers=headers,
    )

    try:
        with urllib.request.urlopen(req, timeout=MALWAREBAZAAR_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            parsed = json.loads(body)
    except Exception as exc:
        return False, None, f"malwarebazaar query failed: {exc}"

    query_status = parsed.get("query_status")

    if _is_hash_not_found_status(query_status):
        return False, None, "hash not found in web"

    if query_status != "ok":
        return False, None, f"malwarebazaar query_status={query_status}"

    data_list = parsed.get("data")

    if not isinstance(data_list, list) or not data_list:
        return False, None, "hash not found in web"

    sample = data_list[0]

    if not isinstance(sample, dict):
        return False, None, "hash not found in web"

    sha256_hash = sample.get("sha256_hash")

    if not isinstance(sha256_hash, str) or not sha256_hash.strip():
        return False, None, "hash not found in web"

    return True, sha256_hash.strip(), "-"


def _download_malwarebazaar_sample(sha256_hash: str, output_zip: str) -> Tuple[bool, str]:
    headers, header_error = _get_malwarebazaar_headers()

    if header_error:
        return False, header_error

    data = urllib.parse.urlencode(
        {
            "query": "get_file",
            "sha256_hash": sha256_hash,
        }
    ).encode()

    req = urllib.request.Request(
        MALWAREBAZAAR_API_URL,
        data=data,
        method="POST",
        headers=headers,
    )

    try:
        with urllib.request.urlopen(req, timeout=MALWAREBAZAAR_TIMEOUT) as resp:
            body = resp.read()
    except Exception as exc:
        return False, f"sample download failed: {exc}"

    if body.startswith(b"{"):
        try:
            parsed = json.loads(body.decode("utf-8", errors="ignore"))
            query_status = parsed.get("query_status")

            if _is_hash_not_found_status(query_status):
                return False, "hash not found in web"

            return False, f"sample download failed: {query_status}"
        except Exception:
            return False, "sample download failed: json error response"

    if not body:
        return False, "hash not found in web"

    Path(output_zip).write_bytes(body)
    return True, "-"


def _extract_zip_with_7z(zip_path: str, output_dir: str) -> Tuple[bool, str]:
    sevenz_bin = _which("7z") or _which("7za")

    if not sevenz_bin:
        return False, "7z command not found"

    cmd = [
        sevenz_bin,
        "x",
        f"-p{MALWARE_ZIP_PASSWORD}",
        "-y",
        f"-o{output_dir}",
        zip_path,
    ]

    code, stdout, stderr = _run_command(cmd, timeout=MALWAREBAZAAR_TIMEOUT)

    if code != 0:
        return False, (stderr or stdout).strip() or "zip extraction failed"

    return True, "-"


def _hash_file_sha256(path: str) -> str:
    h = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)

    return h.hexdigest()


def _iter_files(base_dir: str) -> List[str]:
    result = []

    if not os.path.exists(base_dir):
        return result

    for root, _, files in os.walk(base_dir):
        for name in files:
            result.append(os.path.join(root, name))

    return result


def _run_yara_scan(rule_content: str, target_path: str) -> Tuple[bool, str]:
    yara_bin = _which("yara")

    if not yara_bin:
        return False, "yara command not found"

    with tempfile.TemporaryDirectory(prefix="ctink_yara_run_") as workdir:
        rule_path = os.path.join(workdir, "rule.yar")
        _write_text(rule_path, rule_content + "\n")

        cmd = [yara_bin, rule_path, target_path]
        code, stdout, stderr = _run_command(cmd, timeout=COMMAND_TIMEOUT)

        if code == 0 and stdout.strip():
            return True, stdout.strip()

        if code == 0 and not stdout.strip():
            return False, "no yara match"

        if code == 1:
            return False, "no yara match"

        return False, (stderr or stdout).strip() or "yara scan failed"


def _yara_fn_check(rule_content: str, ioc_list: List[Dict[str, str]]) -> Tuple[str, str]:
    file_hash = ioc_list[0]["ioc_value"]

    found, sha256_hash, feedback = _query_malwarebazaar_hash(file_hash)

    if not found:
        if _is_hash_not_found_feedback(feedback):
            return "fail", "hash not found in web"

        return "fail", feedback

    if not sha256_hash:
        return "fail", "hash not found in web"

    os.makedirs(MALWARE_SAMPLE_DIR, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="ctink_yara_malware_") as workdir:
        zip_path = os.path.join(MALWARE_SAMPLE_DIR, f"{sha256_hash}.zip")
        extract_dir = os.path.join(workdir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)

        ok, feedback = _download_malwarebazaar_sample(sha256_hash, zip_path)

        if not ok:
            if _is_hash_not_found_feedback(feedback):
                return "fail", "hash not found in web"

            return "fail", feedback

        ok, feedback = _extract_zip_with_7z(zip_path, extract_dir)

        if not ok:
            return "fail", feedback

        sample_files = _iter_files(extract_dir)

        if not sample_files:
            return "fail", "hash not found in web"

        for sample_path in sample_files:
            detected, scan_feedback = _run_yara_scan(rule_content, sample_path)

            if detected:
                return "success", "-"

        return "fail", "downloaded sample not detected by yara rule"


def _yara_fp_check(rule_content: str) -> Tuple[str, str]:
    normal_files = _iter_files(NORMAL_YARA_DIR)

    if not normal_files:
        return "fail", f"normal dataset not found or empty: {NORMAL_YARA_DIR}"

    failed = []

    for normal_path in normal_files:
        detected, feedback = _run_yara_scan(rule_content, normal_path)

        if detected:
            failed.append(normal_path)

    if failed:
        return "fail", "failed normal data: " + ", ".join(failed[:20])

    return "success", "-"


def _grammar_check(rule_type: str, rule_content: str) -> Tuple[str, str]:
    if rule_type == "snort":
        return _snort_grammar_check(rule_content)

    if rule_type == "yara":
        return _yara_grammar_check(rule_content)

    return "fail", "unsupported rule_type"


def _fn_check(rule_type: str, rule_content: str, ioc_list: List[Dict[str, str]]) -> Tuple[str, str]:
    if rule_type == "snort":
        return _snort_fn_check(rule_content, ioc_list)

    if rule_type == "yara":
        return _yara_fn_check(rule_content, ioc_list)

    return "fail", "unsupported rule_type"


def _fp_check(rule_type: str, rule_content: str, ioc_list: List[Dict[str, str]]) -> Tuple[str, str]:
    if rule_type == "snort":
        return _snort_fp_check(rule_content, ioc_list)

    if rule_type == "yara":
        return _yara_fp_check(rule_content)

    return "fail", "unsupported rule_type"


def validate_detection_rule(input_json: Dict[str, Any]) -> Dict[str, str]:
    validated, error = _validate_input(input_json)

    if error:
        return _safe_result(
            "fail",
            error,
            "fail",
            "input validation failed",
            "fail",
            "input validation failed",
        )

    rule_type = validated["rule_type"]
    ioc_list = validated["ioc_list"]
    rule_content = validated["rule_content"]

    grammar_result, grammar_feedback = _grammar_check(rule_type, rule_content)

    if grammar_result != "success":
        return _safe_result(
            grammar_result,
            grammar_feedback,
            "fail",
            "skipped because grammar validation failed",
            "fail",
            "skipped because grammar validation failed",
        )

    fn_result, fn_feedback = _fn_check(rule_type, rule_content, ioc_list)
    fp_result, fp_feedback = _fp_check(rule_type, rule_content, ioc_list)

    return _safe_result(
        grammar_result,
        grammar_feedback,
        fn_result,
        fn_feedback,
        fp_result,
        fp_feedback,
    )


def _make_mq_success_response(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "message_type": "rule_validation_response",
        "status": "success",
        "payload": payload,
        "error": None,
    }


def _make_mq_error_response(error_code: str, message: str) -> Dict[str, Any]:
    return {
        "message_type": "rule_validation_response",
        "status": "error",
        "payload": None,
        "error": {
            "code": error_code,
            "message": message,
        },
    }


def _extract_payload_from_mq_json(mq_json: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(mq_json, dict):
        raise TypeError("MQ JSON message must be a dict")

    if mq_json.get("message_type") != "rule_validation_request":
        raise ValueError("message_type must be 'rule_validation_request'")

    payload = mq_json.get("payload")

    if not isinstance(payload, dict):
        raise TypeError("payload must be a dict")

    return payload


def validate_detection_rule_mq_json(mq_json: Dict[str, Any]) -> Dict[str, Any]:
    try:
        payload = _extract_payload_from_mq_json(mq_json)
        result = validate_detection_rule(payload)
        return _make_mq_success_response(result)

    except Exception as exc:
        return _make_mq_error_response("rule_validation_failed", str(exc))


def rule_validation_node(state: Dict[str, Any]) -> Dict[str, Any]:
    mq_request = state.get("mq_json")

    if mq_request is None:
        mq_response = _make_mq_error_response(
            "missing_mq_json",
            "state must contain 'mq_json'",
        )
    else:
        mq_response = validate_detection_rule_mq_json(mq_request)

    return {
        **state,
        "mq_json": mq_response,
    }

if __name__ == "__main__":
    test_input = {
        "rule_type": "snort",
        "ioc_list": [
            {
                "ioc_type": "ip",
                "ioc_value": "192.168.1.1",
            },
            {
                "ioc_type": "domain",
                "ioc_value": "mallllwwwwaaarree.com",
            }
        ],
        "rule_content": 'alert icmp 192.168.1.1 any -> any any (msg:"CTI-NK test malicious ip"; sid:1000001; rev:1;)',
    }
    # test_input = {
    #     "rule_type": "yara",
    #     "ioc_list": [
    #         {
    #             "ioc_type": "hash",
    #             "ioc_value": "7097ac173c2b99772ed4080c0358b007b1c2349203dce4945cb615789d81af30",
    #         }
    #     ],
    #     "rule_content": 'import "hash"\n\nrule CTI_NK_Hash_Test_F19A8BD4 {\n    meta:\n        description = "CTI-NK YARA rule for hash IoC validation test"\n        hash = "7097ac173c2b99772ed4080c0358b007b1c2349203dce4945cb615789d81af30"\n    condition:\n        hash.sha256(0, filesize) == "7097ac173c2b99772ed4080c0358b007b1c2349203dce4945cb615789d81af30"\n}',
    # }

    result = validate_detection_rule(test_input)
    print(json.dumps(result, ensure_ascii=False, indent=2))


