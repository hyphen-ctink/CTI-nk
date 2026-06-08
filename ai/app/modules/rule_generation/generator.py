# 정책 생성 모듈 - Snort(ip/domain/url) / YARA(hash) 분리 생성.

import json
import logging
import re
from typing import Any

from app.integrations.ollama_client import get_rule_generator_client
from app.modules.rule_generation.prompts import (
    build_snort_rule_generation_messages,
    build_yara_rule_generation_messages,
)


logger = logging.getLogger(__name__)

SNORT_IOC_TYPES = frozenset({"ip", "domain", "url"})
YARA_IOC_TYPES = frozenset({"hash"})

SNORT_SID_OFFSET = 1_000_001
DEFAULT_SNORT_SID_START = 1_000_001


def resolve_snort_sid_start(backend_sid: int | None) -> int:
    if backend_sid is None:
        return DEFAULT_SNORT_SID_START
    return SNORT_SID_OFFSET + int(backend_sid)


class RuleGenerationError(Exception):
    pass


def _extract_ioc_value_from_rule(rule_content: str, ioc_type: str) -> str:
    if ioc_type == "ip":
        match = re.search(
            r"alert\s+\w+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
            rule_content,
        )
        return match.group(1) if match else ""
    if ioc_type == "domain":
        match = re.search(r'content:"([^"]+)"', rule_content)
        return match.group(1) if match else ""
    if ioc_type == "url":
        match = re.search(r'uricontent:"([^"]+)"', rule_content)
        if match:
            return match.group(1)
        match = re.search(r'content:"([^"]+)"', rule_content)
        return match.group(1) if match else ""
    if ioc_type == "hash":
        match = re.search(
            r'hash\.(?:sha256|sha1|md5)\([^)]+\)\s*==\s*"([a-fA-F0-9]+)"',
            rule_content,
        )
        return match.group(1) if match else ""
    return ""


def _split_ioc_list(ioc_list: list[dict]) -> tuple[list[dict], list[dict]]:
    snort_iocs = [
        ioc for ioc in ioc_list if ioc.get("ioc_type") in SNORT_IOC_TYPES
    ]
    yara_iocs = [
        ioc for ioc in ioc_list if ioc.get("ioc_type") in YARA_IOC_TYPES
    ]
    return snort_iocs, yara_iocs


def _apply_snort_sid(rule_content: str, snort_sid: int) -> str:
    content = rule_content.strip()
    if not content:
        return content

    if re.search(r"sid:\s*\d+", content):
        content = re.sub(r"sid:\s*\d+", f"sid:{snort_sid}", content, count=1)
    elif content.endswith(")"):
        inner = content[:-1].rstrip()
        if inner.endswith("("):
            content = f"{inner}sid:{snort_sid}; rev:1;)"
        else:
            sep = "" if inner.endswith(";") else "; "
            content = f"{inner}{sep}sid:{snort_sid}; rev:1;)"
    else:
        content = f"{content}; sid:{snort_sid}; rev:1;"

    if not re.search(r"rev:\s*\d+", content):
        content = re.sub(
            r"(sid:\s*\d+;)",
            rf"\1 rev:1;",
            content,
            count=1,
        )
    return content


def _strip_uricontent(rule_content: str) -> str:
    cleaned = re.sub(r'uricontent:"[^"]*";\s*', "", rule_content)
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned


def _normalize_snort_msg(rule_content: str, attack_type: str, ioc_type: str) -> str:
    ioc_value = _extract_ioc_value_from_rule(rule_content, ioc_type)
    if not ioc_value:
        return rule_content

    type_upper = attack_type.upper().replace(" ", "_")
    if ioc_type == "ip":
        new_msg = f"CTINK {type_upper} from {ioc_value}"
    elif ioc_type == "domain":
        new_msg = f"CTINK {type_upper} domain {ioc_value}"
    elif ioc_type == "url":
        new_msg = f"CTINK {type_upper} URL {ioc_value}"
    else:
        return rule_content

    return re.sub(
        r'msg:"[^"]*"',
        f'msg:"{new_msg}"',
        rule_content,
        count=1,
    )


def _extract_json_from_response(response_text: str) -> dict[str, Any]:
    code_block_pattern = r"```(?:json)?\s*(\{.*?\})\s*```"
    match = re.search(code_block_pattern, response_text, re.DOTALL)
    if match:
        json_str = match.group(1)
    else:
        start = response_text.find("{")
        end = response_text.rfind("}")
        if start == -1 or end == -1 or end < start:
            raise RuleGenerationError(
                f"응답에서 JSON을 찾을 수 없습니다: {response_text[:200]}"
            )
        json_str = response_text[start : end + 1]

    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        raise RuleGenerationError(f"JSON 파싱 실패: {e}. 응답: {json_str[:200]}")


def _normalize_detection_rules(
    rules: list[dict],
    attack_type: str = "",
    base_sid: int = 1000001,
) -> list[dict]:
    normalized = []
    snort_sid = base_sid
    seen_yara_hashes = set()
    seen_snort_content = set()

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        ioc_type = rule.get("ioc_type", "")
        rule_type = rule.get("rule_type", "")
        rule_content = rule.get("rule_content", "")
        if not ioc_type or not rule_type or not rule_content:
            continue
        if rule_type not in ("snort", "yara"):
            continue

        if rule_type == "snort":
            logger.info(f"[normalize] 모델원본: {rule_content!r}")

            if ioc_type in ("domain", "url"):
                rule_content = _strip_uricontent(rule_content)

            dedup_key = _extract_ioc_value_from_rule(rule_content, "domain")
            if dedup_key and dedup_key in seen_snort_content:
                logger.info(f"[normalize] 중복 snort 룰 스킵: {dedup_key}")
                continue
            if dedup_key:
                seen_snort_content.add(dedup_key)

            rule_content = _apply_snort_sid(rule_content, snort_sid)
            snort_sid += 1

            if attack_type:
                rule_content = _normalize_snort_msg(rule_content, attack_type, ioc_type)
            logger.info(f"[normalize] 정규화후: {rule_content!r}")

        if rule_type == "yara":
            hash_val = _extract_ioc_value_from_rule(rule_content, "hash")
            if hash_val and hash_val in seen_yara_hashes:
                logger.info(f"[normalize] 중복 hash YARA 룰 스킵: {hash_val}")
                continue
            if hash_val:
                seen_yara_hashes.add(hash_val)

        normalized.append({
            "ioc_type": ioc_type,
            "rule_type": rule_type,
            "rule_content": rule_content,
        })

    return normalized


def _invoke_rule_model(messages: list) -> dict[str, Any]:
    client = get_rule_generator_client()
    response = client.invoke(messages)
    return _extract_json_from_response(response.content)


def _generate_snort_rules(
    attack_type: str,
    snort_iocs: list[dict],
    base_sid: int,
    previous_attempt: str = "",
    feedback: str = "",
    is_ioc_only: bool = False,
) -> list[dict]:
    if not snort_iocs:
        return []

    messages = build_snort_rule_generation_messages(
        attack_type=attack_type,
        ioc_list=snort_iocs,
        base_sid=base_sid,
        previous_attempt=previous_attempt,
        feedback=feedback,
        is_ioc_only=is_ioc_only,
    )
    parsed = _invoke_rule_model(messages)
    raw_rules = parsed.get("detection_rule") or parsed.get("rules") or []
    if not isinstance(raw_rules, list):
        raise RuleGenerationError("Snort 룰 배열이 아닙니다")

    return _normalize_detection_rules(
        raw_rules, attack_type=attack_type, base_sid=base_sid
    )


def _generate_yara_rules(
    attack_type: str,
    yara_iocs: list[dict],
    previous_attempt: str = "",
    feedback: str = "",
    is_ioc_only: bool = False,
) -> list[dict]:
    if not yara_iocs:
        return []

    messages = build_yara_rule_generation_messages(
        attack_type=attack_type,
        ioc_list=yara_iocs,
        previous_attempt=previous_attempt,
        feedback=feedback,
        is_ioc_only=is_ioc_only,
    )
    parsed = _invoke_rule_model(messages)
    raw_rules = parsed.get("detection_rule") or parsed.get("rules") or []
    if not isinstance(raw_rules, list):
        raise RuleGenerationError("YARA 룰 배열이 아닙니다")

    return _normalize_detection_rules(raw_rules, attack_type=attack_type)


def generate_rules(
    attack_type: str, ioc_list: list[dict], previous_attempt: str = "",
    feedback: str = "", base_sid: int = 1000001, is_ioc_only: bool = False,
) -> dict[str, Any]:
    if not ioc_list:
        return {"detection_rule": []}

    snort_iocs, yara_iocs = _split_ioc_list(ioc_list)
    detection_rule: list[dict] = []

    logger.info(
        f"[rule_generation] 동일 Ollama 모델 · Snort 호출={bool(snort_iocs)} "
        f"YARA 호출={bool(yara_iocs)}, snort sid 시작={base_sid}, is_ioc_only={is_ioc_only}"
    )

    if snort_iocs:
        snort_rules = _generate_snort_rules(
            attack_type=attack_type,
            snort_iocs=snort_iocs,
            base_sid=base_sid,
            previous_attempt=previous_attempt,
            feedback=feedback,
            is_ioc_only=is_ioc_only,
        )
        detection_rule.extend(snort_rules)

    if yara_iocs:
        yara_rules = _generate_yara_rules(
            attack_type=attack_type,
            yara_iocs=yara_iocs,
            previous_attempt=previous_attempt,
            feedback=feedback,
            is_ioc_only=is_ioc_only,
        )
        detection_rule.extend(yara_rules)

    if not detection_rule:
        raise RuleGenerationError(
            "정규화 후 유효한 룰이 없습니다. 모델 응답 검토 필요."
        )

    logger.info(f"[rule_generation] 최종 룰 {len(detection_rule)}개 생성")
    return {"detection_rule": detection_rule}
