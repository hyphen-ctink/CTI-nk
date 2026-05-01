# cti_analyzer.py
#
# 실행 전 환경변수 설정:
#   export ANTHROPIC_API_KEY="sk-ant-..."
#   export CLAUDE_MODEL="claude-sonnet-4-5"
#
# 설치:
#   pip install anthropic
#
# 로컬 테스트:
#   python3 cti_analyzer.py
#
# 일반 함수 호출:
#   from cti_analyzer import analyze_cti
#   result = analyze_cti({
#       "platform_id": 1,
#       "raw_content": "원문 CTI 텍스트"
#   })
#
# LangGraph MQ JSON 호출:
#   from cti_analyzer import analyze_cti_mq_json
#   mq_result = analyze_cti_mq_json({
#       "message_type": "cti_analysis_request",
#       "payload": {
#           "platform_id": 1,
#           "raw_content": "원문 CTI 텍스트"
#       }
#   })
#

import os
import json
import time
from typing import Any, Dict, List, Optional

from anthropic import Anthropic


KNOWN_ATTACK_TYPES = {
    "web_attack",
    "ransomware",
    "phishing",
    "ddos",
    "credential_stuffing",
}

IOC_BUNDLE_ATTACK_TYPES = {
    "network_attack",
    "host-system_attack",
    "mixed_ioc_attack",
}

ALL_ATTACK_TYPES = {
    "web_attack",
    "ransomware",
    "phishing",
    "ddos",
    "credential_stuffing",
    "unknown",
    "network_attack",
    "host-system_attack",
    "mixed_ioc_attack",
}

DETAIL_SCHEMAS = {
    "web_attack": {
        "attack_category": None,
        "injection_location": None,
        "special_char_included": None,
        "encoding_used": None,
        "sql_keyword_included": None,
        "script_tag_included": None,
        "os_command_included": None,
    },
    "ransomware": {
        "threat_group": None,
        "c2_ip_address": None,
        "c2_domain_address": None,
        "malicious_domain_address": None,
        "malicious_url_address": None,
        "file_hash": None,
        "file_name": None,
        "file_path": None,
        "ransom_note": None,
    },
    "phishing": {
        "attack_category": None,
        "delivery_method": None,
        "target_system": None,
        "target_brand": None,
        "email_characteristics": None,
        "ip_used": None,
        "domain_age_days": None,
        "attachment_exists": None,
        "attachment_extension": None,
        "double_extension_used": None,
    },
    "ddos": {
        "attack_category": None,
        "attack_scale_pps": None,
        "attack_scale_bps": None,
        "attack_started_at": None,
        "attack_ended_at": None,
        "attack_duration_seconds": None,
        "source_ip_address": None,
        "source_port": None,
        "destination_ip_address": None,
        "destination_port": None,
        "protocol_used": None,
        "botnet_name": None,
    },
    "credential_stuffing": {
        "target_service": None,
        "multiple_ip_used": None,
        "multiple_accounts_used": None,
        "automated_attack": None,
    },
}

BOOLEAN_FIELDS = {
    "encoding_used",
    "ip_used",
    "attachment_exists",
    "double_extension_used",
    "multiple_ip_used",
    "multiple_accounts_used",
    "automated_attack",
}

INTEGER_FIELDS = {
    "domain_age_days",
    "attack_scale_pps",
    "attack_scale_bps",
    "attack_duration_seconds",
    "source_port",
    "destination_port",
}

IOC_TYPES = {
    "ip",
    "domain",
    "url",
    "hash",
}


SYSTEM_PROMPT = """
You are a CTI JSON extraction module.

The raw CTI can be Korean, English, mixed Korean-English, structured JSON, STIX-like text, markdown, AsciiDoc, table fragments, or a messy collection of IoCs.
Analyze the CTI regardless of language or format.
The summary must always be written in English.

Very important:
- Do not assume raw_content is always an article.
- First decide whether raw_content is primarily:
  1. an attack narrative/content report, or
  2. an IoC bundle/list/table/indicator collection.
- This decision must be made by you from the raw_content.
- Extract IoCs yourself from the raw_content.
- IoC values may be defanged, fragmented, inside tables, inside JSON, inside STIX patterns, or mixed with headings/noise.
- Examples:
  - 1.2.3[.]4
  - example[.]com
  - hxxp://example[.]com/a
  - hxxps://example[.]com/a
  - [url:value = 'https://example.com/']
  - [domain-name:value = 'example.com']
  - [file:hashes.SHA256 = 'abcdef...']
  - table rows containing hashes, domains, URLs, or IPs.
- Normalize defanged IoCs:
  - [.] becomes .
  - hxxp becomes http
  - hxxps becomes https
- Only extract IoC types: ip, domain, url, hash.
- Do not invent IoCs.
- Do not extract generic website links as malicious IoCs unless they are clearly listed as indicators or part of the threat infrastructure.

Attack type decision rules:

A. If raw_content is primarily an IoC bundle/list/table/indicator collection and does not contain enough attack narrative to infer one of the five known attack types:
   - If all extracted IoCs are only ip/domain/url, return:
     "attack_type": "network_attack"
   - If all extracted IoCs are only hash, return:
     "attack_type": "host-system_attack"
   - If extracted IoCs include both network IoCs(ip/domain/url) and hash IoCs, return:
     "attack_type": "mixed_ioc_attack"
   - For network_attack, host-system_attack, mixed_ioc_attack:
     Do not return attack_detail.
   - For network_attack, host-system_attack, mixed_ioc_attack:
     summary must be exactly the same string as attack_type.

B. If raw_content is an attack narrative/content report:
   - Classify into exactly one primary attack_type from:
     web_attack, ransomware, phishing, ddos, credential_stuffing.
   - Choose the closest one.
   - If none of the five types is appropriate, return:
     "attack_type": "unknown"
   - Do not return multiple attack types.

Return JSON only.
No markdown.
No explanation.

Output format for IoC bundle types:
{
  "attack_type": "network_attack|host-system_attack|mixed_ioc_attack",
  "summary": "network_attack|host-system_attack|mixed_ioc_attack",
  "ioc_list": [
    {
      "ioc_type": "ip|domain|url|hash",
      "ioc_value": "string"
    }
  ]
}

Output format for unknown:
{
  "attack_type": "unknown",
  "summary": "One-sentence English summary.",
  "ioc_list": [
    {
      "ioc_type": "ip|domain|url|hash",
      "ioc_value": "string"
    }
  ]
}

Output format for known attack types:
{
  "attack_type": "web_attack|ransomware|phishing|ddos|credential_stuffing",
  "attack_detail": [
    {
      "attack_type": "same attack_type",
      "detail": {}
    }
  ],
  "summary": "One-sentence English attack summary.",
  "ioc_list": [
    {
      "ioc_type": "ip|domain|url|hash",
      "ioc_value": "string"
    }
  ]
}

Known type detail schemas:

web_attack:
{
  "attack_category": "string or null",
  "injection_location": "string or null",
  "special_char_included": "string or null",
  "encoding_used": "boolean or null",
  "sql_keyword_included": "string or null",
  "script_tag_included": "string or null",
  "os_command_included": "string or null"
}

ransomware:
{
  "threat_group": "string or null",
  "c2_ip_address": "string or null",
  "c2_domain_address": "string or null",
  "malicious_domain_address": "string or null",
  "malicious_url_address": "string or null",
  "file_hash": "string or null",
  "file_name": "string or null",
  "file_path": "string or null",
  "ransom_note": "string or null"
}

phishing:
{
  "attack_category": "string or null",
  "delivery_method": "string or null",
  "target_system": "string or null",
  "target_brand": "string or null",
  "email_characteristics": "string or null",
  "ip_used": "boolean or null",
  "domain_age_days": "integer or null",
  "attachment_exists": "boolean or null",
  "attachment_extension": "string or null",
  "double_extension_used": "boolean or null"
}

ddos:
{
  "attack_category": "string or null",
  "attack_scale_pps": "integer or null",
  "attack_scale_bps": "integer or null",
  "attack_started_at": "string datetime or null",
  "attack_ended_at": "string datetime or null",
  "attack_duration_seconds": "integer or null",
  "source_ip_address": "string or null",
  "source_port": "integer or null",
  "destination_ip_address": "string or null",
  "destination_port": "integer or null",
  "protocol_used": "string or null",
  "botnet_name": "string or null"
}

credential_stuffing:
{
  "target_service": "string or null",
  "multiple_ip_used": "boolean or null",
  "multiple_accounts_used": "boolean or null",
  "automated_attack": "boolean or null"
}

Rules:
- If a detail value is missing or cannot be extracted, return null for that field.
- If no IoC exists, return "ioc_list": null.
- Do not include fields outside the schema.
- Keep summary as one English sentence except for IoC bundle types.
- For IoC bundle types, summary must equal attack_type exactly.
"""


def _load_env_file_if_exists(path: str = ".env") -> None:
    if not os.path.exists(path):
        return

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")

            if key and key not in os.environ:
                os.environ[key] = value


def _get_anthropic_client() -> Anthropic:
    _load_env_file_if_exists()

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is missing. "
            "Set it with: export ANTHROPIC_API_KEY='sk-ant-...'"
        )

    return Anthropic(api_key=api_key)


def _limit_raw_content(raw_content: str) -> str:
    max_chars = int(os.getenv("CTI_MAX_INPUT_CHARS", "12000"))
    raw_content = raw_content.strip()

    if len(raw_content) <= max_chars:
        return raw_content

    return raw_content[:max_chars]


def _extract_json_object(text: str) -> Dict[str, Any]:
    text = text.strip()

    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    if text.startswith("```"):
        lines = text.splitlines()

        if lines and lines[0].strip().startswith("```"):
            lines = lines[1:]

        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]

        cleaned = "\n".join(lines).strip()

        try:
            parsed = json.loads(cleaned)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    start = text.find("{")
    end = text.rfind("}")

    if start == -1 or end == -1 or end <= start:
        raise ValueError("Claude response does not contain a JSON object.")

    parsed = json.loads(text[start : end + 1])

    if not isinstance(parsed, dict):
        raise ValueError("Claude response JSON is not an object.")

    return parsed


def _as_bool_or_none(value: Any) -> Optional[bool]:
    if value is None:
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        normalized = value.strip().lower()

        if normalized in {"true", "yes", "y", "1", "included", "used", "present"}:
            return True

        if normalized in {"false", "no", "n", "0", "not included", "not used", "absent"}:
            return False

    if isinstance(value, int):
        return value != 0

    return None


def _as_int_or_none(value: Any) -> Optional[int]:
    if value is None:
        return None

    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        return value

    if isinstance(value, float):
        return int(value)

    if isinstance(value, str):
        cleaned = value.strip().replace(",", "")

        if cleaned == "":
            return None

        try:
            return int(cleaned)
        except ValueError:
            return None

    return None


def _as_string_or_none(value: Any) -> Optional[str]:
    if value is None:
        return None

    if isinstance(value, str):
        stripped = value.strip()
        return stripped if stripped else None

    return str(value)


def _normalize_attack_type(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None

    normalized = value.strip().lower().replace("-", "_").replace(" ", "_")

    alias_map = {
        "web": "web_attack",
        "webattack": "web_attack",
        "web_attack": "web_attack",
        "sql_injection": "web_attack",
        "sqli": "web_attack",
        "xss": "web_attack",
        "cross_site_scripting": "web_attack",
        "command_injection": "web_attack",
        "os_command_injection": "web_attack",

        "ransom": "ransomware",
        "ransomware": "ransomware",

        "phishing": "phishing",
        "credential_phishing": "phishing",

        "ddos": "ddos",
        "dos": "ddos",
        "distributed_denial_of_service": "ddos",

        "credential_stuffing": "credential_stuffing",
        "credentialstuffing": "credential_stuffing",
        "account_takeover": "credential_stuffing",
        "ato": "credential_stuffing",

        "network": "network_attack",
        "network_attack": "network_attack",
        "network_ioc": "network_attack",
        "network_ioc_attack": "network_attack",
        "network_indicators": "network_attack",

        "host": "host-system_attack",
        "host_system": "host-system_attack",
        "host_system_attack": "host-system_attack",
        "host-system": "host-system_attack",
        "host-system_attack": "host-system_attack",
        "hash_attack": "host-system_attack",
        "hash_ioc": "host-system_attack",
        "hash_indicators": "host-system_attack",
        "file_hash_indicators": "host-system_attack",

        "mixed": "mixed_ioc_attack",
        "mixed_ioc": "mixed_ioc_attack",
        "mixed_ioc_attack": "mixed_ioc_attack",
        "mixed_indicators": "mixed_ioc_attack",

        "unknown": "unknown",
        "other": "unknown",
        "new": "unknown",
        "new_type": "unknown",
    }

    return alias_map.get(normalized)


def _normalize_ioc_type(value: Any) -> str:
    if not isinstance(value, str):
        return "other"

    normalized = value.strip().lower().replace("-", "_").replace(" ", "_")

    alias_map = {
        "ipv4": "ip",
        "ipv6": "ip",
        "ip_address": "ip",
        "ip": "ip",
        "domain": "domain",
        "domain_name": "domain",
        "hostname": "domain",
        "host": "domain",
        "url": "url",
        "uri": "url",
        "md5": "hash",
        "sha1": "hash",
        "sha_1": "hash",
        "sha256": "hash",
        "sha_256": "hash",
        "sha512": "hash",
        "sha_512": "hash",
        "hash": "hash",
        "file_hash": "hash",
    }

    mapped = alias_map.get(normalized)

    if mapped in IOC_TYPES:
        return mapped

    return "other"


def _normalize_detail(attack_type: str, detail: Any) -> Dict[str, Any]:
    schema = DETAIL_SCHEMAS.get(attack_type, {})

    if not isinstance(detail, dict):
        detail = {}

    normalized: Dict[str, Any] = {}

    for key in schema.keys():
        raw_value = detail.get(key)

        if key in BOOLEAN_FIELDS:
            normalized[key] = _as_bool_or_none(raw_value)

        elif key in INTEGER_FIELDS:
            normalized[key] = _as_int_or_none(raw_value)

        else:
            normalized[key] = _as_string_or_none(raw_value)

    return normalized


def _normalize_attack_detail(attack_type: str, value: Any) -> List[Dict[str, Any]]:
    if attack_type in {"unknown"} or attack_type in IOC_BUNDLE_ATTACK_TYPES:
        return []

    if isinstance(value, list):
        raw_items = value
    elif isinstance(value, dict):
        raw_items = [value]
    else:
        raw_items = []

    if not raw_items:
        raw_items = [{"attack_type": attack_type, "detail": {}}]

    normalized_items: List[Dict[str, Any]] = []

    for item in raw_items:
        if not isinstance(item, dict):
            continue

        item_attack_type = _normalize_attack_type(item.get("attack_type"))

        if item_attack_type not in KNOWN_ATTACK_TYPES:
            item_attack_type = attack_type

        detail = item.get("detail", {})

        normalized_items.append(
            {
                "attack_type": item_attack_type,
                "detail": _normalize_detail(item_attack_type, detail),
            }
        )

    if not normalized_items:
        normalized_items.append(
            {
                "attack_type": attack_type,
                "detail": _normalize_detail(attack_type, {}),
            }
        )

    return normalized_items


def _normalize_ioc_list(value: Any) -> Optional[List[Dict[str, str]]]:
    if not isinstance(value, list):
        return None

    result: List[Dict[str, str]] = []
    seen = set()

    for item in value:
        if not isinstance(item, dict):
            continue

        ioc_type = _normalize_ioc_type(item.get("ioc_type"))
        ioc_value = _as_string_or_none(item.get("ioc_value"))

        if ioc_type not in IOC_TYPES:
            continue

        if not ioc_value:
            continue

        if ioc_type == "hash":
            ioc_value = ioc_value.lower()

        dedupe_key = (ioc_type, ioc_value.lower())

        if dedupe_key in seen:
            continue

        seen.add(dedupe_key)

        result.append(
            {
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
            }
        )

    return result if result else None


def _validate_classification(raw_output: Dict[str, Any]) -> str:
    attack_type = _normalize_attack_type(raw_output.get("attack_type"))

    if attack_type not in ALL_ATTACK_TYPES:
        raise ValueError("attack_type classification failed or invalid.")

    return attack_type


def _normalize_output(raw_output: Dict[str, Any]) -> Dict[str, Any]:
    attack_type = _validate_classification(raw_output)

    summary = _as_string_or_none(raw_output.get("summary"))
    if summary is None:
        summary = "The CTI report describes cyber threat information, but no clear summary could be extracted."

    ioc_list = _normalize_ioc_list(raw_output.get("ioc_list"))

    if attack_type in IOC_BUNDLE_ATTACK_TYPES:
        return {
            "attack_type": attack_type,
            "summary": attack_type,
            "ioc_list": ioc_list,
        }

    if attack_type == "unknown":
        return {
            "attack_type": "unknown",
            "summary": summary,
            "ioc_list": ioc_list,
        }

    attack_detail = _normalize_attack_detail(
        attack_type,
        raw_output.get("attack_detail"),
    )

    return {
        "attack_type": attack_type,
        "attack_detail": attack_detail,
        "summary": summary,
        "ioc_list": ioc_list,
    }


def _validate_input(input_json: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(input_json, dict):
        raise TypeError("input_json must be a dict.")

    if "platform_id" not in input_json:
        raise ValueError("input_json must contain 'platform_id'.")

    if "raw_content" not in input_json:
        raise ValueError("input_json must contain 'raw_content'.")

    platform_id = input_json["platform_id"]
    raw_content = input_json["raw_content"]

    if not isinstance(platform_id, int):
        raise TypeError("'platform_id' must be an integer.")

    if not isinstance(raw_content, str):
        raise TypeError("'raw_content' must be a string.")

    raw_content = _limit_raw_content(raw_content)

    if not raw_content:
        raise ValueError("'raw_content' must not be empty.")

    return {
        "platform_id": platform_id,
        "raw_content": raw_content,
    }


def _call_claude(input_json: Dict[str, Any]) -> Dict[str, Any]:
    client = _get_anthropic_client()

    model = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-5")
    max_tokens = int(os.getenv("CLAUDE_MAX_TOKENS", "2048"))

    user_prompt = {
        "platform_id": input_json["platform_id"],
        "raw_content": input_json["raw_content"],
    }

    response = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        temperature=0,
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": json.dumps(user_prompt, ensure_ascii=False),
            }
        ],
    )

    text_parts: List[str] = []

    for block in response.content:
        if getattr(block, "type", None) == "text":
            text_parts.append(block.text)

    if not text_parts:
        raise RuntimeError("Claude response does not contain text content.")

    response_text = "\n".join(text_parts).strip()
    return _extract_json_object(response_text)


def analyze_cti(input_json: Dict[str, Any]) -> Dict[str, Any]:
    # 일반 Python dict 입력/출력 함수.
    # 로컬 테스트와 내부 분석 로직에서 사용한다.

    try:
        validated_input = _validate_input(input_json)
    except Exception as exc:
        return {
            "error": "invalid_input",
            "message": str(exc),
            "attack_type": None,
            "summary": None,
            "ioc_list": None,
        }

    max_attempts = int(os.getenv("CLAUDE_CLASSIFICATION_MAX_ATTEMPTS", "3"))
    last_error: Optional[Exception] = None

    for attempt in range(1, max_attempts + 1):
        try:
            raw_output = _call_claude(validated_input)
            _validate_classification(raw_output)
            return _normalize_output(raw_output)

        except Exception as exc:
            last_error = exc

            if attempt >= max_attempts:
                break

            time.sleep(1.2 * attempt)

    return {
        "error": "classification_failed",
        "message": f"attack_type classification failed after {max_attempts} attempts: {last_error}",
        "attack_type": None,
        "summary": None,
        "ioc_list": None,
    }


def _make_mq_success_response(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "message_type": "cti_analysis_response",
        "status": "success",
        "payload": payload,
        "error": None,
    }


def _make_mq_error_response(error_code: str, message: str) -> Dict[str, Any]:
    return {
        "message_type": "cti_analysis_response",
        "status": "error",
        "payload": None,
        "error": {
            "code": error_code,
            "message": message,
        },
    }


def _extract_payload_from_mq_json(mq_json: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(mq_json, dict):
        raise TypeError("MQ JSON message must be a dict.")

    message_type = mq_json.get("message_type")
    if message_type != "cti_analysis_request":
        raise ValueError("message_type must be 'cti_analysis_request'.")

    payload = mq_json.get("payload")
    if not isinstance(payload, dict):
        raise TypeError("payload must be a dict.")

    return payload


def analyze_cti_mq_json(mq_json: Dict[str, Any]) -> Dict[str, Any]:
    # LangGraph/MQ 통신용 함수.
    # 입력 MQ JSON:
    # {
    #   "message_type": "cti_analysis_request",
    #   "payload": {
    #       "platform_id": 1,
    #       "raw_content": "원문 CTI 텍스트"
    #   }
    # }
    #
    # 출력 MQ JSON:
    # {
    #   "message_type": "cti_analysis_response",
    #   "status": "success" | "error",
    #   "payload": {분석 결과} | null,
    #   "error": null | {"code": "...", "message": "..."}
    # }

    try:
        payload = _extract_payload_from_mq_json(mq_json)
    except Exception as exc:
        return _make_mq_error_response("invalid_mq_json", str(exc))

    result = analyze_cti(payload)

    if isinstance(result, dict) and "error" in result:
        return _make_mq_error_response(
            str(result.get("error")),
            str(result.get("message")),
        )

    return _make_mq_success_response(result)


def cti_analysis_node(state: Dict[str, Any]) -> Dict[str, Any]:
    # LangGraph 노드용 함수.
    # state["mq_json"]에 MQ JSON 요청을 넣으면,
    # state["mq_json"]에 MQ JSON 응답을 다시 넣어서 반환한다.
    #
    # 입력 state 예:
    # {
    #   "mq_json": {
    #       "message_type": "cti_analysis_request",
    #       "payload": {
    #           "platform_id": 1,
    #           "raw_content": "원문 CTI 텍스트"
    #       }
    #   }
    # }

    mq_request = state.get("mq_json")

    if mq_request is None:
        mq_response = _make_mq_error_response(
            "missing_mq_json",
            "state must contain 'mq_json'.",
        )
    else:
        mq_response = analyze_cti_mq_json(mq_request)

    return {
        **state,
        "mq_json": mq_response,
    }


if __name__ == "__main__":
    test_input =   {
    "platform_id": 3,
    "raw_content": "calxabank[.]info"
  }

    result = analyze_cti(test_input)
    print(json.dumps(result, ensure_ascii=False, indent=2))
