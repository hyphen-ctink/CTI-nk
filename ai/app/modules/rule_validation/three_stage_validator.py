#3단계 정책 검증 모듈 (문법/미탐/오탐).

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
        "hash_not_found", "file_not_found", "not_found",
        "no_results", "no_result", "not_found_or_no_api_access",
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


def _run_command(cmd: List[str], timeout: int = COMMAND_TIMEOUT, cwd: Optional[str] = None) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, cwd=cwd, timeout=timeout, capture_output=True, text=True)
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


def _safe_result(grammar_result, grammar_feedback, fn_result, fn_feedback, fp_result, fp_feedback) -> Dict[str, str]:
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
        normalized_iocs.append({"ioc_type": ioc_type, "ioc_value": ioc_value})
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
    yarac_bin = _which("yarac")
    if yarac_bin:
        with tempfile.TemporaryDirectory(prefix="ctink_yara_grammar_") as workdir:
            rule_path = os.path.join(workdir, "rule.yar")
            compiled_path = os.path.join(workdir, "compiled_rule.yarc")
            _write_text(rule_path, rule_content + "\n")
            cmd = [yarac_bin, rule_path, compiled_path]
            code, stdout, stderr = _run_command(cmd, timeout=COMMAND_TIMEOUT)
            if code == 0:
                return "success", "-"
            return "fail", (stderr or stdout).strip() or "yara grammar check failed"
    yara_bin = _which("yara")
    if not yara_bin:
        return "fail", "yara/yarac command not found"
    with tempfile.TemporaryDirectory(prefix="ctink_yara_grammar_") as workdir:
        rule_path = os.path.join(workdir, "rule.yar")
        target_path = os.path.join(workdir, "empty_target.bin")
        _write_text(rule_path, rule_content + "\n")
        Path(target_path).write_bytes(b"")
        cmd = [yara_bin, rule_path, target_path]
        code, stdout, stderr = _run_command(cmd, timeout=COMMAND_TIMEOUT)
        feedback = (stderr or stdout).strip()
        if feedback:
            return "fail", feedback
        if code == 0:
            return "success", "-"
        return "fail", "yara grammar check failed"


def _import_scapy():
    try:
        from scapy.all import Ether, IP, ICMP, TCP, Raw, wrpcap
        return Ether, IP, ICMP, TCP, Raw, wrpcap, None
    except Exception as exc:
        return None, None, None, None, None, None, str(exc)


def _extract_dst_port_from_rule(rule_content: str, default: int = 80) -> int:
    """Snort 룰에서 목적지 포트 추출. 'alert tcp any any -> any 443 (' → 443, 'any'면 default."""
    import re
    match = re.search(r'->\s*\S+\s+(\d+)\s*\(', rule_content)
    if match:
        return int(match.group(1))
    return default


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


def _make_snort_attack_pcap(ioc_type: str, ioc_value: str, pcap_path: str, rule_content: str = "") -> Optional[str]:
    Ether, IP, ICMP, TCP, Raw, wrpcap, err = _import_scapy()
    if err:
        return f"scapy import failed: {err}"
    packets = []
    if ioc_type == "ip":
        packets.append(Ether() / IP(src=ioc_value, dst="127.0.0.1") / ICMP())
        packets.append(Ether() / IP(src=ioc_value, dst="127.0.0.1") / TCP(sport=44444, dport=80, flags="S", seq=1))
    elif ioc_type in {"domain", "url"}:
        payload = _http_payload_for_ioc(ioc_type, ioc_value)
        dport = _extract_dst_port_from_rule(rule_content, default=80)
        packets.append(
            Ether() / IP(src="10.10.10.10", dst="127.0.0.1")
            / TCP(sport=44444, dport=dport, flags="PA", seq=1, ack=1)
            / Raw(load=payload)
        )
    else:
        return f"unsupported snort ioc_type: {ioc_type}"
    wrpcap(pcap_path, packets)
    return None


def _make_snort_normal_pcap(ioc_type: str, normal_value: str, pcap_path: str, rule_content: str = "") -> Optional[str]:
    Ether, IP, ICMP, TCP, Raw, wrpcap, err = _import_scapy()
    if err:
        return f"scapy import failed: {err}"
    packets = []
    if ioc_type == "ip":
        packets.append(Ether() / IP(src=normal_value, dst="127.0.0.1") / ICMP())
    elif ioc_type in {"domain", "url"}:
        payload = _http_payload_for_ioc(ioc_type, normal_value)
        dport = _extract_dst_port_from_rule(rule_content, default=80)
        packets.append(
            Ether() / IP(src="10.20.30.40", dst="127.0.0.1")
            / TCP(sport=45454, dport=dport, flags="PA", seq=1, ack=1)
            / Raw(load=payload)
        )
    else:
        return f"unsupported snort ioc_type: {ioc_type}"
    wrpcap(pcap_path, packets)
    return None


def _make_snort_normal_batch_pcap(
    ioc_type: str,
    normal_values: List[str],
    pcap_path: str,
    rule_content: str = "",
) -> Optional[str]:
    Ether, IP, ICMP, TCP, Raw, wrpcap, err = _import_scapy()

    if err:
        return f"scapy import failed: {err}"

    packets = []
    dport = _extract_dst_port_from_rule(rule_content, default=80)

    try:
        for normal_value in normal_values:
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
                    / TCP(sport=45454, dport=dport, flags="PA", seq=1, ack=1)
                    / Raw(load=payload)
                )

            else:
                return f"unsupported snort ioc_type: {ioc_type}"

        if not packets:
            return "normal dataset is empty"

        wrpcap(pcap_path, packets)
        return None

    except Exception as exc:
        return f"normal pcap generation failed: {exc}"


def _run_snort_pcap(rule_content: str, pcap_path: str) -> Tuple[bool, str]:
    rule_content = re.sub(r';\s*http_uri\b', '', rule_content)
    rule_content = re.sub(r';\s*http_header\b', '', rule_content)
    rule_content = re.sub(r';\s*http_method\b', '', rule_content)
    rule_content = re.sub(r';\s*http_client_body\b', '', rule_content)
    rule_content = re.sub(r'\buricontent:', 'content:', rule_content)
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
            cmd = [snort_bin, "-q", "-A", "fast", "-c", conf_path, "-r", pcap_path, "-l", logdir]
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
            err = _make_snort_attack_pcap(ioc_type, ioc_value, pcap_path, rule_content)  # rule_content 추가
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


def _snort_fp_precise_check_type(
    rule_content: str,
    ioc_type: str,
    normal_values: List[str],
    workdir: str,
) -> List[str]:
    failed = []

    for idx, normal_value in enumerate(normal_values):
        pcap_path = os.path.join(workdir, f"normal_{ioc_type}_{idx}.pcap")

        err = _make_snort_normal_pcap(ioc_type, normal_value, pcap_path, rule_content)

        if err:
            failed.append(f"{ioc_type}:{normal_value} ({err})")
            continue

        alerted, feedback = _run_snort_pcap(rule_content, pcap_path)

        if alerted:
            failed.append(f"{ioc_type}:{normal_value} (false positive)")
            break

    return failed


def _snort_fp_check(rule_content: str, ioc_list: List[Dict[str, str]]) -> Tuple[str, str]:
    failed = []
    checked_ioc_types = set()
    with tempfile.TemporaryDirectory(prefix="ctink_snort_fp_") as workdir:
        for ioc in ioc_list:
            ioc_type = ioc["ioc_type"]
            if ioc_type in checked_ioc_types:
                continue
            checked_ioc_types.add(ioc_type)
            normal_file = os.path.join(NORMAL_SNORT_DIR, f"{ioc_type}.txt")
            normal_values = _read_lines(normal_file, limit=100)
            if not normal_values:
                return "fail", f"normal dataset not found or empty: {normal_file}"
            batch_pcap_path = os.path.join(workdir, f"normal_{ioc_type}_batch.pcap")
            err = _make_snort_normal_batch_pcap(ioc_type, normal_values, batch_pcap_path, rule_content)
            if err:
                failed.append(f"{ioc_type}:batch ({err})")
                continue
            alerted, feedback = _run_snort_pcap(rule_content, batch_pcap_path)
            if not alerted:
                continue               
            failed.extend(
                _snort_fp_precise_check_type(
                    rule_content,
                    ioc_type,
                    normal_values,
                    workdir,
                )
            )

    if failed:
        return "fail", "failed normal data: " + ", ".join(failed)
    return "success", "-"


def _query_malwarebazaar_hash(file_hash: str) -> Tuple[bool, Optional[str], str]:
    headers, header_error = _get_malwarebazaar_headers()
    if header_error:
        return False, None, header_error
    data = urllib.parse.urlencode({"query": "get_info", "hash": file_hash}).encode()
    req = urllib.request.Request(MALWAREBAZAAR_API_URL, data=data, method="POST", headers=headers)
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
    data = urllib.parse.urlencode({"query": "get_file", "sha256_hash": sha256_hash}).encode()
    req = urllib.request.Request(MALWAREBAZAAR_API_URL, data=data, method="POST", headers=headers)
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
    cmd = [sevenz_bin, "x", f"-p{MALWARE_ZIP_PASSWORD}", "-y", f"-o{output_dir}", zip_path]
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
            "fail", error,
            "fail", "input validation failed",
            "fail", "input validation failed",
        )
    rule_type = validated["rule_type"]
    ioc_list = validated["ioc_list"]
    rule_content = validated["rule_content"]
    grammar_result, grammar_feedback = _grammar_check(rule_type, rule_content)
    if grammar_result != "success":
        return _safe_result(
            grammar_result, grammar_feedback,
            "fail", "skipped because grammar validation failed",
            "fail", "skipped because grammar validation failed",
        )
    fn_result, fn_feedback = _fn_check(rule_type, rule_content, ioc_list)
    fp_result, fp_feedback = _fp_check(rule_type, rule_content, ioc_list)
    return _safe_result(
        grammar_result, grammar_feedback,
        fn_result, fn_feedback,
        fp_result, fp_feedback,
    )



class ThreeStageValidationError(Exception):
    pass


def _normalize_result_value(value: str) -> str:
    if value == "fail":
        return "failure"
    return value


def _filter_iocs_for_rule_type(
    rule_type: str,
    ioc_list: List[Dict[str, str]],
) -> List[Dict[str, str]]:
    if rule_type == "snort":
        return [
            ioc for ioc in ioc_list
            if ioc.get("ioc_type") in SNORT_IOC_TYPES
        ]
    elif rule_type == "yara":
        hashes = [
            ioc for ioc in ioc_list
            if ioc.get("ioc_type") in YARA_IOC_TYPES
        ]
        return hashes[:1] if hashes else []
    return []


def run_three_stage_validation(
    rule_type: str,
    rule_content: str,
    ioc_list: List[Dict[str, str]],
) -> Dict[str, Any]:
    if rule_type not in ("snort", "yara"):
        raise ThreeStageValidationError(
            f"지원하지 않는 룰 유형: {rule_type} (snort/yara만 허용)"
        )
    if not rule_content or not rule_content.strip():
        raise ThreeStageValidationError("rule_content가 비어 있습니다.")
    
    filtered_iocs = _filter_iocs_for_rule_type(rule_type, ioc_list)
    
    if not filtered_iocs:
        return {
            "grammar_result": "failure",
            "grammar_feedback": f"{rule_type} 룰에 적합한 IoC가 없습니다.",
            "fn_result": "failure",
            "fn_feedback": "skipped",
            "fp_result": "failure",
            "fp_feedback": "skipped",
        }
    
    input_payload = {
        "rule_type": rule_type,
        "ioc_list": filtered_iocs,
        "rule_content": rule_content,
    }
    
    raw_result = validate_detection_rule(input_payload)
    
    return {
        "grammar_result": _normalize_result_value(raw_result.get("grammar_result", "failure")),
        "grammar_feedback": raw_result.get("grammar_feedback", ""),
        "fn_result": _normalize_result_value(raw_result.get("fn_result", "failure")),
        "fn_feedback": raw_result.get("fn_feedback", ""),
        "fp_result": _normalize_result_value(raw_result.get("fp_result", "failure")),
        "fp_feedback": raw_result.get("fp_feedback", ""),
    }