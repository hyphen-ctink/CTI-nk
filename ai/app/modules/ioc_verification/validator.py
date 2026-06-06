#IoC 검증 모듈

import json
import re
from typing import Any

from app.integrations.ollama_client import invoke_ioc_validator
from app.modules.ioc_verification.external_tools import (
    query_virustotal_via_tavily,
    is_ioc_in_raw_content,
)
from app.modules.ioc_verification.prompts import build_ioc_validation_prompt


VALID_RESULTS = {"success", "re-extraction", "removed"}


class IoCValidationError(Exception):
    pass


def _extract_json_from_response(response_text: str) -> dict[str, Any]:
    code_block_pattern = r"```(?:json)?\s*(\{.*?\})\s*```"
    match = re.search(code_block_pattern, response_text, re.DOTALL)
    if match:
        json_str = match.group(1)
    else:
        start = response_text.find("{")
        end = response_text.rfind("}")
        if start == -1 or end == -1 or end < start:
            raise IoCValidationError(
                f"응답에서 JSON을 찾을 수 없습니다: {response_text[:200]}"
            )
        json_str = response_text[start : end + 1]
    
    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        raise IoCValidationError(
            f"JSON 파싱 실패: {e}. 응답: {json_str[:200]}"
        )


def _build_external_info_summary(ioc_list: list[dict]) -> tuple[str, str]:
    summary_lines = []
    any_malicious = False
    
    for ioc in ioc_list:
        ioc_value = ioc.get("ioc_value", "")
        ioc_type = ioc.get("ioc_type", "")
        
        result = query_virustotal_via_tavily(ioc_value, ioc_type)
        
        if result["error"]:
            summary_lines.append(f"- {ioc_value}: 조회 실패 ({result['error']})")
            continue
        
        malicious_count = len(result["malicious_indicators"])
        if malicious_count > 0:
            any_malicious = True
            summary_lines.append(
                f"- {ioc_value} ({ioc_type}): 악성 관련 정보 {malicious_count}건 발견"
            )
        else:
            summary_lines.append(
                f"- {ioc_value} ({ioc_type}): 악성 관련 정보 없음"
            )
    
    summary_text = "\n".join(summary_lines) if summary_lines else "(조회 결과 없음)"
    virustotal_result = "true" if any_malicious else "false"
    
    return summary_text, virustotal_result


def _pre_check_iocs_in_source(
    raw_content: str,
    ioc_list: list[dict],
) -> list[dict]:
    return [
        {
            "ioc_value": ioc.get("ioc_value", ""),
            "ioc_type": ioc.get("ioc_type", ""),
            "in_source": is_ioc_in_raw_content(
                ioc.get("ioc_value", ""), raw_content
            ),
        }
        for ioc in ioc_list
    ]


def validate_iocs(
    raw_content: str,
    ioc_list: list[dict],
) -> dict[str, Any]:
    if not raw_content or not raw_content.strip():
        raise IoCValidationError("raw_content가 비어 있습니다.")
    if not ioc_list:
        return {
            "virustotal_result": "false",
            "ioc_list": [],
            "result": "success",
            "feedback": "",
        }
    
    external_info, virustotal_result = _build_external_info_summary(ioc_list)
    
    prompt = build_ioc_validation_prompt(
        raw_content=raw_content,
        ioc_list=ioc_list,
        virustotal_result=virustotal_result,
    )
    response_text = invoke_ioc_validator(prompt)
    
    parsed = _extract_json_from_response(response_text)
    
    raw_result = str(parsed.get("result", "")).lower().strip()
    if raw_result not in VALID_RESULTS:
        raw_result = "removed"
    
    feedback = parsed.get("feedback", "")
    if not isinstance(feedback, str):
        feedback = str(feedback)
    
    return {
        "virustotal_result": virustotal_result,
        "ioc_list": ioc_list,
        "result": raw_result,
        "feedback": feedback,
    }