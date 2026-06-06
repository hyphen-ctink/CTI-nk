#정책 검증 에이전트 - 룰의 의미적 품질을 종합 분석.


import json
import re
from typing import Any

from app.integrations.ollama_client import get_rule_validator_client
from app.modules.rule_validation.prompts import (
    build_rule_validation_messages,
    map_quality_to_result,
)


class ValidationAgentError(Exception):
    pass


def _url_to_domain(url_value: str) -> str:
    v = url_value.strip()
    v = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", v)
    v = v.split("/")[0]   
    v = v.split(":")[0]
    return v


def _extract_json_from_response(response_text: str) -> dict[str, Any]:
    code_block_pattern = r"```(?:json)?\s*(\{.*?\})\s*```"
    match = re.search(code_block_pattern, response_text, re.DOTALL)
    if match:
        json_str = match.group(1)
    else:
        start = response_text.find("{")
        end = response_text.rfind("}")
        if start == -1 or end == -1 or end < start:
            raise ValidationAgentError(
                f"JSON 추출 실패: {response_text[:200]}"
            )
        json_str = response_text[start : end + 1]
    
    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValidationAgentError(f"JSON 파싱 실패: {e}")


def _attack_detail_to_features(attack_detail: list[dict]) -> str:
    if not attack_detail:
        return ""
    
    features = []
    
    for entry in attack_detail:
        attack_type = entry.get("attack_type", "")
        detail = entry.get("detail", {})
        
        if not isinstance(detail, dict):
            continue
        
        if detail.get("c2_ip_address") or detail.get("c2_domain_address"):
            features.append("C2 communication observed")
        if detail.get("malicious_domain_address"):
            features.append("Malicious domain distribution")
        if detail.get("malicious_url_address"):
            features.append("Malicious URL delivery")
        if detail.get("file_hash"):
            features.append("Malicious file artifact")
        if detail.get("file_name") or detail.get("file_path"):
            features.append("Suspicious file system activity")
        if detail.get("ransom_note"):
            features.append("Ransom note characteristics observed")
    
    # 기본 패턴
    if not features:
        defaults = {
            "phishing": "Impersonation target: login portal, Delivery: phishing campaign, Credential harvesting attempt",
            "ransomware": "Encryption behavior observed, C2 communication, File system modification",
            "web_attack": "Web application targeting, Malicious request pattern, Server-side exploitation attempt",
            "ddos": "Traffic flooding pattern, Volumetric attack, Service disruption attempt",
            "malware": "Malicious binary execution, Persistence mechanism, System compromise",
        }
        return defaults.get(attack_type, f"Standard {attack_type} attack pattern")
    # 중복 제거 + 결합
    seen = set()
    unique_features = []
    for f in features:
        if f not in seen:
            seen.add(f)
            unique_features.append(f)
    
    return ", ".join(unique_features)


def judge_validation_result(
    rule_type: str,
    rule_content: str,
    ioc_list: list[dict],
    attack_type: str,
    three_stage_result: dict[str, Any],
    attack_detail: list[dict] | None = None,
    current_retry_count: int = 0,
    max_retry: int = 3,
) -> dict[str, Any]:
    grammar_failed = three_stage_result.get("grammar_result") == "failure"
    fn_failed = three_stage_result.get("fn_result") == "failure"
    fp_failed = three_stage_result.get("fp_result") == "failure"
    
    if grammar_failed or fn_failed or fp_failed:
        if current_retry_count >= max_retry:
            return {
                "result": "removed",
                "feedback": _build_three_stage_feedback(
                    three_stage_result, grammar_failed, fn_failed, fp_failed,
                    retry_exceeded=True,
                    retry_count=current_retry_count,
                ),
            }
        
        return {
            "result": "re-generation",
            "feedback": _build_three_stage_feedback(
                three_stage_result, grammar_failed, fn_failed, fp_failed,
            ),
        }
    
    attack_features = _attack_detail_to_features(attack_detail or [])
    
    validation_ioc_list = [
        {**ioc, "ioc_value": _url_to_domain(ioc.get("ioc_value", ""))}
        if ioc.get("ioc_type") == "url" else ioc
        for ioc in ioc_list
    ]
    
    messages = build_rule_validation_messages(
        rule_type=rule_type,
        rule_content=rule_content,
        ioc_list=validation_ioc_list,
        attack_type=attack_type,
        attack_features=attack_features,
    )
    
    import logging
    logger = logging.getLogger(__name__)
    logger.info("=" * 70)
    logger.info("[judge_validation] sLLM에 보내는 메시지:")
    for i, msg in enumerate(messages):
        logger.info(f"  Message {i} ({type(msg).__name__}):")
        content = msg.content if hasattr(msg, 'content') else str(msg)
        logger.info(f"  {content}")
    logger.info("=" * 70)

    client = get_rule_validator_client()
    response = client.invoke(messages)
    response_text = response.content

    logger.info("[judge_validation] sLLM 응답 원본:")
    logger.info(f"  {response_text}")
    logger.info("=" * 70)

    parsed = _extract_json_from_response(response_text)
    
    quality_score = str(parsed.get("quality_score", "low")).lower().strip()
    regeneration_needed = bool(parsed.get("regeneration_needed", True))
    model_feedback = parsed.get("feedback", "")
    if not isinstance(model_feedback, str):
        model_feedback = str(model_feedback)
    
    if quality_score not in ("high", "medium", "low"):
        quality_score = "low"

    if quality_score in ("high", "medium") and regeneration_needed:
        import logging
        regeneration_needed = False
        model_feedback = "-"
    
    result = map_quality_to_result(
        quality_score=quality_score,
        regeneration_needed=regeneration_needed,
        current_retry_count=current_retry_count,
        max_retry=max_retry,
    )
    
    if result == "success":
        feedback_text = "" if model_feedback == "-" else model_feedback
    else:
        feedback_text = model_feedback
    
    return {
        "result": result,
        "feedback": feedback_text,
    }


def _build_three_stage_feedback(
    three_stage_result: dict,
    grammar_failed: bool,
    fn_failed: bool,
    fp_failed: bool,
    retry_exceeded: bool = False,
    retry_count: int = 0,
) -> str:
    messages = []
    if grammar_failed:
        msg = three_stage_result.get('grammar_feedback', '')
        messages.append(f"Grammar 실패: {msg}")
    if fn_failed:
        msg = three_stage_result.get('fn_feedback', '')
        messages.append(f"FN 실패: {msg}")
    if fp_failed:
        msg = three_stage_result.get('fp_feedback', '')
        messages.append(f"FP 실패: {msg}")
    
    feedback = " | ".join(messages)
    
    if retry_exceeded:
        feedback = f"재시도 {retry_count}회 한도 초과. {feedback}"
    
    return feedback