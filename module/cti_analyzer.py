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
    "IOC_ONLY",
}

ALL_ATTACK_TYPES = {
    "web_attack",
    "ransomware",
    "phishing",
    "ddos",
    "credential_stuffing",
    "unknown",
    "IOC_ONLY",
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
   - Always return:
     "attack_type": "IOC_ONLY"
   - Do not return attack_detail.
   - summary must be exactly:
     "IOC_ONLY"

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
  "attack_type": "IOC_ONLY",
  "summary": "IOC_ONLY",
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

        "ioc_only": "IOC_ONLY",
        "ioc_bundle": "IOC_ONLY",
        "ioc_list": "IOC_ONLY",
        "indicator_bundle": "IOC_ONLY",
        "indicator_list": "IOC_ONLY",
        "network": "IOC_ONLY",
        "network_attack": "IOC_ONLY",
        "network_ioc": "IOC_ONLY",
        "network_ioc_attack": "IOC_ONLY",
        "network_indicators": "IOC_ONLY",
        "host": "IOC_ONLY",
        "host_system": "IOC_ONLY",
        "host_system_attack": "IOC_ONLY",
        "host-system": "IOC_ONLY",
        "host-system_attack": "IOC_ONLY",
        "hash_attack": "IOC_ONLY",
        "hash_ioc": "IOC_ONLY",
        "hash_indicators": "IOC_ONLY",
        "file_hash_indicators": "IOC_ONLY",
        "mixed": "IOC_ONLY",
        "mixed_ioc": "IOC_ONLY",
        "mixed_ioc_attack": "IOC_ONLY",
        "mixed_indicators": "IOC_ONLY",

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
    "platform_id": 4,
    "raw_content": "{\"type\": \"bundle\", \"spec_version\": \"2.0\", \"id\": \"bundle--a572b04d-1f33-436a-adf6-fc879d7c3ed7\", \"objects\": [{\"type\": \"identity\", \"id\": \"identity--5df15c12-89fc-45a7-9620-0044ac110004\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"Talos\", \"identity_class\": \"organization\"}, {\"type\": \"report\", \"id\": \"report--112e0515-7d87-4d7b-a555-f6439b0732e9\", \"created_by_ref\": \"identity--5df15c12-89fc-45a7-9620-0044ac110004\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"The n8n n8mare: How threat actors are misusing AI workflow automation\", \"published\": \"2026-04-14T20:54:13Z\", \"object_refs\": [\"observed-data--ba5f5119-3702-4802-8e32-cf061bac7a51\", \"indicator--460f3e77-db65-4ed7-88a1-5ddb0cfbd3ee\", \"indicator--f69f7493-1a59-41ac-9dfd-08cf3c71e273\", \"indicator--84be0261-fc01-421c-8f32-811d03283f44\", \"indicator--28f94c63-76bc-4e34-bb70-48859f4fbea1\", \"indicator--fa63fc02-7947-424d-8707-c8cb60c24fc9\", \"indicator--cecb04c7-e853-44e6-8bbb-ca4315a96ab4\", \"attack-pattern--b6301b64-ef57-4cce-bb0b-77026f14a8db\", \"attack-pattern--241814ae-de3f-4656-b49e-f9a80764d4b7\", \"attack-pattern--d157f9d2-d09a-4efa-bb2a-64963f94e253\", \"attack-pattern--1ecb2399-e8ba-4f6b-8ba7-5c27d49405cf\", \"attack-pattern--3d333250-30e4-4a82-9edc-756c68afc529\", \"attack-pattern--d4536441-1bcc-49fa-80ae-a596ed3f7ffd\", \"attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830\", \"attack-pattern--457c7820-d331-465a-915e-42f85500ccc4\", \"attack-pattern--57340c81-c025-4189-8fa0-fc7ede51bae4\", \"attack-pattern--b3d682b6-98f2-4fb0-aa3b-b4df007ca70a\", \"attack-pattern--aedfca76-3b30-4866-b2aa-0f1d7fd1e4b6\", \"attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add\", \"attack-pattern--82caa33e-d11a-433a-94ea-9b5a5fbef81d\", \"attack-pattern--391d824f-0ef1-47a0-b0ee-c59a75e27670\", \"attack-pattern--b83e166d-13d7-4b52-8677-dff90c548fd7\", \"attack-pattern--106c0cf6-bf73-4601-9aa8-0945c2715ec5\", \"attack-pattern--42e8de7b-37b2-4258-905a-6897815e58e0\", \"attack-pattern--799ace7f-e227-4411-baa0-8868704f2a69\", \"attack-pattern--54a649ff-439a-41a4-9856-8d144a2551ba\", \"attack-pattern--4061e78c-1284-44b4-9116-73e4ac3912f7\", \"attack-pattern--a8c31121-852b-46bd-9ba4-674ae5afe7ad\", \"attack-pattern--e4dc8c01-417f-458d-9ee0-bb0617c1b391\", \"attack-pattern--92a78814-b191-47ca-909c-1ccfe3777414\"], \"labels\": [\"Threat-Report\", \"misp:tool=\\\"MISP-STIX-Converter\\\"\", \" TLP:WHITE\", \"Talos_Intel_Blog\"]}, {\"type\": \"observed-data\", \"id\": \"observed-data--ba5f5119-3702-4802-8e32-cf061bac7a51\", \"created_by_ref\": \"identity--5df15c12-89fc-45a7-9620-0044ac110004\", \"created\": \"2026-04-14T20:38:51.000Z\", \"modified\": \"2026-04-14T20:38:51.000Z\", \"first_observed\": \"2026-04-14T20:38:51Z\", \"last_observed\": \"2026-04-14T20:38:51Z\", \"number_observed\": 1, \"objects\": {\"0\": {\"type\": \"url\", \"value\": \"blog.talosintelligence.com/the-n8n-n8mare/\"}}, \"labels\": [\"misp:type=\\\"url\\\"\", \"misp:category=\\\"External analysis\\\"\"]}, {\"type\": \"indicator\", \"id\": \"indicator--460f3e77-db65-4ed7-88a1-5ddb0cfbd3ee\", \"created_by_ref\": \"identity--5df15c12-89fc-45a7-9620-0044ac110004\", \"created\": \"2026-04-14T20:39:37.000Z\", \"modified\": \"2026-04-14T20:39:37.000Z\", \"pattern\": \"[file:hashes.SHA256 = '7f30259d72eb7432b2454c07be83365ecfa835188185b35b30d11654aadf86a0']\", \"valid_from\": \"2026-04-14T20:39:37Z\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"Payload delivery\"}], \"labels\": [\"misp:type=\\\"sha256\\\"\", \"misp:category=\\\"Payload delivery\\\"\", \"misp:to_ids=\\\"True\\\"\"]}, {\"type\": \"indicator\", \"id\": \"indicator--f69f7493-1a59-41ac-9dfd-08cf3c71e273\", \"created_by_ref\": \"identity--5df15c12-89fc-45a7-9620-0044ac110004\", \"created\": \"2026-04-14T20:39:37.000Z\", \"modified\": \"2026-04-14T20:39:37.000Z\", \"pattern\": \"[file:hashes.SHA256 = '93a09e54e607930dfc068fcbc7ea2c2ea776c504aa20a8ca12100a28cfdcc75a']\", \"valid_from\": \"2026-04-14T20:39:37Z\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"Payload delivery\"}], \"labels\": [\"misp:type=\\\"sha256\\\"\", \"misp:category=\\\"Payload delivery\\\"\", \"misp:to_ids=\\\"True\\\"\"]}, {\"type\": \"indicator\", \"id\": \"indicator--84be0261-fc01-421c-8f32-811d03283f44\", \"created_by_ref\": \"identity--5df15c12-89fc-45a7-9620-0044ac110004\", \"created\": \"2026-04-14T20:40:08.000Z\", \"modified\": \"2026-04-14T20:40:08.000Z\", \"pattern\": \"[url:value = 'https://onedrivedownload.zoholandingpage.com/my-workspace/DownloadedOneDrive']\", \"valid_from\": \"2026-04-14T20:40:08Z\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"Network activity\"}], \"labels\": [\"misp:type=\\\"url\\\"\", \"misp:category=\\\"Network activity\\\"\", \"misp:to_ids=\\\"True\\\"\"]}, {\"type\": \"indicator\", \"id\": \"indicator--28f94c63-76bc-4e34-bb70-48859f4fbea1\", \"created_by_ref\": \"identity--5df15c12-89fc-45a7-9620-0044ac110004\", \"created\": \"2026-04-14T20:40:08.000Z\", \"modified\": \"2026-04-14T20:40:08.000Z\", \"pattern\": \"[url:value = 'https://majormetalcsorp.com/Openfolder']\", \"valid_from\": \"2026-04-14T20:40:08Z\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"Network activity\"}], \"labels\": [\"misp:type=\\\"url\\\"\", \"misp:category=\\\"Network activity\\\"\", \"misp:to_ids=\\\"True\\\"\"]}, {\"type\": \"indicator\", \"id\": \"indicator--fa63fc02-7947-424d-8707-c8cb60c24fc9\", \"created_by_ref\": \"identity--5df15c12-89fc-45a7-9620-0044ac110004\", \"created\": \"2026-04-14T20:40:08.000Z\", \"modified\": \"2026-04-14T20:40:08.000Z\", \"pattern\": \"[url:value = 'https://pagepoinnc.app.n8n.cloud/webhook/downloading-1a92cb4f-cff3-449d-8bdd-ec439b4b3496']\", \"valid_from\": \"2026-04-14T20:40:08Z\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"Network activity\"}], \"labels\": [\"misp:type=\\\"url\\\"\", \"misp:category=\\\"Network activity\\\"\", \"misp:to_ids=\\\"True\\\"\"]}, {\"type\": \"indicator\", \"id\": \"indicator--cecb04c7-e853-44e6-8bbb-ca4315a96ab4\", \"created_by_ref\": \"identity--5df15c12-89fc-45a7-9620-0044ac110004\", \"created\": \"2026-04-14T20:40:08.000Z\", \"modified\": \"2026-04-14T20:40:08.000Z\", \"pattern\": \"[url:value = 'https://monicasue.app.n8n.cloud/webhook/download-file-92684bb4-ee1d-4806-a264-50bfeb750dab']\", \"valid_from\": \"2026-04-14T20:40:08Z\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"Network activity\"}], \"labels\": [\"misp:type=\\\"url\\\"\", \"misp:category=\\\"Network activity\\\"\", \"misp:to_ids=\\\"True\\\"\"]}, {\"type\": \"attack-pattern\", \"id\": \"attack-pattern--b6301b64-ef57-4cce-bb0b-77026f14a8db\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"Event Triggered Execution - T1546\", \"description\": \"ATT&CK Tactic | Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution based on specific events. Various operating systems have means to monitor and subscribe to events such as logons or other user activity such as running specific applications/binaries. \\n\\nAdversaries may abuse these mechanisms as a means of maintaining persistent access to a victim via repeatedly executing malicious code. After gaining access to a victim system, adversaries may create/modify event triggers to point to malicious content that will be executed whenever the event trigger is invoked.(Citation: FireEye WMI 2015)(Citation: Malware Persistence on OS X)(Citation: amnesia malware)\\n\\nSince the execution can be proxied by an account with higher permissions, such as SYSTEM or service accounts, an adversary may be able to abuse these triggered execution mechanisms to escalate their privileges. \", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"mitre-attack-pattern\"}], \"labels\": [\"misp:galaxy-name=\\\"Attack Pattern\\\"\", \"misp:galaxy-type=\\\"mitre-attack-pattern\\\"\", \"misp-galaxy:mitre-attack-pattern=\\\"Event Triggered Execution - T1546\\\"\"], \"external_references\": [{\"source_name\": \"mitre-attack\", \"external_id\": \"T1546\"}]}, {\"type\": \"attack-pattern\", \"id\": \"attack-pattern--241814ae-de3f-4656-b49e-f9a80764d4b7\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"Security Software Discovery - T1063\", \"description\": \"ATT&CK Tactic | Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on the system. This may include things such as local firewall rules and anti-virus. Adversaries may use the information from [Security Software Discovery](https://attack.mitre.org/techniques/T1063) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.\\n\\n\\n### Windows\\n\\nExample commands that can be used to obtain security software information are [netsh](https://attack.mitre.org/software/S0108), <code>reg query</code> with [Reg](https://attack.mitre.org/software/S0075), <code>dir</code> with [cmd](https://attack.mitre.org/software/S0106), and [Tasklist](https://attack.mitre.org/software/S0057), but other indicators of discovery behavior may be more specific to the type of software or security system the adversary is looking for.\\n\\n### Mac\\n\\nIt's becoming more common to see macOS malware perform checks for LittleSnitch and KnockKnock software.\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"mitre-attack-pattern\"}], \"labels\": [\"misp:galaxy-name=\\\"Attack Pattern\\\"\", \"misp:galaxy-type=\\\"mitre-attack-pattern\\\"\", \"misp-galaxy:mitre-attack-pattern=\\\"Security Software Discovery - T1063\\\"\"], \"external_references\": [{\"source_name\": \"mitre-attack\", \"external_id\": \"T1063\"}]}, {\"type\": \"attack-pattern\", \"id\": \"attack-pattern--d157f9d2-d09a-4efa-bb2a-64963f94e253\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"System Services - T1569\", \"description\": \"ATT&CK Tactic | Adversaries may abuse system services or daemons to execute commands or programs. Adversaries can execute malicious content by interacting with or creating services either locally or remotely. Many services are set to run at boot, which can aid in achieving persistence ([Create or Modify System Process](https://attack.mitre.org/techniques/T1543)), but adversaries can also abuse services for one-time or temporary execution.\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"mitre-attack-pattern\"}], \"labels\": [\"misp:galaxy-name=\\\"Attack Pattern\\\"\", \"misp:galaxy-type=\\\"mitre-attack-pattern\\\"\", \"misp-galaxy:mitre-attack-pattern=\\\"System Services - T1569\\\"\"], \"external_references\": [{\"source_name\": \"mitre-attack\", \"external_id\": \"T1569\"}]}, {\"type\": \"attack-pattern\", \"id\": \"attack-pattern--1ecb2399-e8ba-4f6b-8ba7-5c27d49405cf\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"Boot or Logon Autostart Execution - T1547\", \"description\": \"ATT&CK Tactic | Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems. Operating systems may have mechanisms for automatically running a program on system boot or account logon.(Citation: Microsoft Run Key)(Citation: MSDN Authentication Packages)(Citation: Microsoft TimeProvider)(Citation: Cylance Reg Persistence Sept 2013)(Citation: Linux Kernel Programming) These mechanisms may include automatically executing programs that are placed in specially designated directories or are referenced by repositories that store configuration information, such as the Windows Registry. An adversary may achieve the same goal by modifying or extending features of the kernel.\\n\\nSince some boot or logon autostart programs run with higher privileges, an adversary may leverage these to elevate privileges.\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"mitre-attack-pattern\"}], \"labels\": [\"misp:galaxy-name=\\\"Attack Pattern\\\"\", \"misp:galaxy-type=\\\"mitre-attack-pattern\\\"\", \"misp-galaxy:mitre-attack-pattern=\\\"Boot or Logon Autostart Execution - T1547\\\"\"], \"external_references\": [{\"source_name\": \"capec\", \"external_id\": \"CAPEC-564\"}]}, {\"type\": \"attack-pattern\", \"id\": \"attack-pattern--3d333250-30e4-4a82-9edc-756c68afc529\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"Impair Defenses - T1562\", \"description\": \"ATT&CK Tactic | Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms. This not only involves impairing preventative defenses, such as firewalls and anti-virus, but also detection capabilities that defenders can use to audit activity and identify malicious behavior. This may also span both native defenses as well as supplemental capabilities installed by users and administrators.\\n\\nAdversaries could also target event aggregation and analysis mechanisms, or otherwise disrupt these procedures by altering other system components.\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"mitre-attack-pattern\"}], \"labels\": [\"misp:galaxy-name=\\\"Attack Pattern\\\"\", \"misp:galaxy-type=\\\"mitre-attack-pattern\\\"\", \"misp-galaxy:mitre-attack-pattern=\\\"Impair Defenses - T1562\\\"\"], \"external_references\": [{\"source_name\": \"mitre-attack\", \"external_id\": \"T1562\"}]}, {\"type\": \"attack-pattern\", \"id\": \"attack-pattern--d4536441-1bcc-49fa-80ae-a596ed3f7ffd\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"System Network Configuration Discovery - T1422\", \"description\": \"ATT&CK Tactic | On Android, details of onboard network interfaces are accessible to apps through the `java.net.NetworkInterface` class.(Citation: NetworkInterface) The Android `TelephonyManager` class can be used to gather related information such as the IMSI, IMEI, and phone number.(Citation: TelephonyManager)\\n\\nOn iOS, gathering network configuration information is not possible without root access.\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"mitre-attack-pattern\"}], \"labels\": [\"misp:galaxy-name=\\\"Attack Pattern\\\"\", \"misp:galaxy-type=\\\"mitre-attack-pattern\\\"\", \"misp-galaxy:mitre-attack-pattern=\\\"System Network Configuration Discovery - T1422\\\"\"], \"external_references\": [{\"source_name\": \"mitre-attack\", \"external_id\": \"T1422\"}]}, {\"type\": \"attack-pattern\", \"id\": \"attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"Command and Scripting Interpreter - T1059\", \"description\": \"ATT&CK Tactic | Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms. Most systems come with some built-in command-line interface and scripting capabilities, for example, macOS and Linux distributions include some flavor of [Unix Shell](https://attack.mitre.org/techniques/T1059/004) while Windows installations include the [Windows Command Shell](https://attack.mitre.org/techniques/T1059/003) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).\\n\\nThere are also cross-platform interpreters such as [Python](https://attack.mitre.org/techniques/T1059/006), as well as those commonly associated with client applications such as [JavaScript](https://attack.mitre.org/techniques/T1059/007) and [Visual Basic](https://attack.mitre.org/techniques/T1059/005).\\n\\nAdversaries may abuse these technologies in various ways as a means of executing arbitrary commands. Commands and scripts can be embedded in [Initial Access](https://attack.mitre.org/tactics/TA0001) payloads delivered to victims as lure documents or as secondary payloads downloaded from an existing C2. Adversaries may also execute commands through interactive terminals/shells, as well as utilize various [Remote Services](https://attack.mitre.org/techniques/T1021) in order to achieve remote Execution.(Citation: Powershell Remote Commands)(Citation: Cisco IOS Software Integrity Assurance - Command History)(Citation: Remote Shell Execution in Python)\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"mitre-attack-pattern\"}], \"labels\": [\"misp:galaxy-name=\\\"Attack Pattern\\\"\", \"misp:galaxy-type=\\\"mitre-attack-pattern\\\"\", \"misp-galaxy:mitre-attack-pattern=\\\"Command and Scripting Interpreter - T1059\\\"\"], \"external_references\": [{\"source_name\": \"mitre-attack\", \"external_id\": \"T1059\"}]}, {\"type\": \"attack-pattern\", \"id\": \"attack-pattern--457c7820-d331-465a-915e-42f85500ccc4\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"System Binary Proxy Execution - T1218\", \"description\": \"ATT&CK Tactic | Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed, or otherwise trusted, binaries. Binaries used in this technique are often Microsoft-signed files, indicating that they have been either downloaded from Microsoft or are already native in the operating system.(Citation: LOLBAS Project) Binaries signed with trusted digital certificates can typically execute on Windows systems protected by digital signature validation. Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files or commands.\\n\\nSimilarly, on Linux systems adversaries may abuse trusted binaries such as <code>split</code> to proxy execution of malicious commands.(Citation: split man page)(Citation: GTFO split)\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"mitre-attack-pattern\"}], \"labels\": [\"misp:galaxy-name=\\\"Attack Pattern\\\"\", \"misp:galaxy-type=\\\"mitre-attack-pattern\\\"\", \"misp-galaxy:mitre-attack-pattern=\\\"System Binary Proxy Execution - T1218\\\"\"], \"external_references\": [{\"source_name\": \"mitre-attack\", \"external_id\": \"T1218\"}]}, {\"type\": \"attack-pattern\", \"id\": \"attack-pattern--57340c81-c025-4189-8fa0-fc7ede51bae4\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"Modify Registry - T1112\", \"description\": \"ATT&CK Tactic | Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.\\n\\nAccess to specific areas of the Registry depends on account permissions, some requiring administrator-level access. The built-in Windows command-line utility [Reg](https://attack.mitre.org/software/S0075) may be used for local or remote Registry modification. (Citation: Microsoft Reg) Other tools may also be used, such as a remote access tool, which may contain functionality to interact with the Registry through the Windows API.\\n\\nRegistry modifications may also include actions to hide keys, such as prepending key names with a null character, which will cause an error and/or be ignored when read via [Reg](https://attack.mitre.org/software/S0075) or other utilities using the Win32 API. (Citation: Microsoft Reghide NOV 2006) Adversaries may abuse these pseudo-hidden keys to conceal payloads/commands used to maintain persistence. (Citation: TrendMicro POWELIKS AUG 2014) (Citation: SpectorOps Hiding Reg Jul 2017)\\n\\nThe Registry of a remote system may be modified to aid in execution of files as part of lateral movement. It requires the remote Registry service to be running on the target system. (Citation: Microsoft Remote) Often [Valid Accounts](https://attack.mitre.org/techniques/T1078) are required, along with access to the remote system's [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) for RPC communication.\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"mitre-attack-pattern\"}], \"labels\": [\"misp:galaxy-name=\\\"Attack Pattern\\\"\", \"misp:galaxy-type=\\\"mitre-attack-pattern\\\"\", \"misp-galaxy:mitre-attack-pattern=\\\"Modify Registry - T1112\\\"\"], \"external_references\": [{\"source_name\": \"capec\", \"external_id\": \"CAPEC-203\"}]}, {\"type\": \"attack-pattern\", \"id\": \"attack-pattern--b3d682b6-98f2-4fb0-aa3b-b4df007ca70a\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"Obfuscated Files or Information - T1027\", \"description\": \"ATT&CK Tactic | Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses. \\n\\nPayloads may be compressed, archived, or encrypted in order to avoid detection. These payloads may be used during Initial Access or later to mitigate detection. Sometimes a user's action may be required to open and [Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140) for [User Execution](https://attack.mitre.org/techniques/T1204). The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary. (Citation: Volexity PowerDuke November 2016) Adversaries may also used compressed or archived scripts, such as JavaScript. \\n\\nPortions of files can also be encoded to hide the plain-text strings that would otherwise help defenders with discovery. (Citation: Linux/Cdorked.A We Live Security Analysis) Payloads may also be split into separate, seemingly benign files that only reveal malicious functionality when reassembled. (Citation: Carbon Black Obfuscation Sept 2016)\\n\\nAdversaries may also obfuscate commands executed from payloads or directly via a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059). Environment variables, aliases, characters, and other platform/language specific semantics can be used to evade signature based detections and application control mechanisms. (Citation: FireEye Obfuscation June 2017) (Citation: FireEye Revoke-Obfuscation July 2017)(Citation: PaloAlto EncodedCommand March 2017) \", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"mitre-attack-pattern\"}], \"labels\": [\"misp:galaxy-name=\\\"Attack Pattern\\\"\", \"misp:galaxy-type=\\\"mitre-attack-pattern\\\"\", \"misp-galaxy:mitre-attack-pattern=\\\"Obfuscated Files or Information - T1027\\\"\"], \"external_references\": [{\"source_name\": \"capec\", \"external_id\": \"CAPEC-267\"}]}, {\"type\": \"attack-pattern\", \"id\": \"attack-pattern--aedfca76-3b30-4866-b2aa-0f1d7fd1e4b6\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"Hijack Execution Flow - T1574\", \"description\": \"ATT&CK Tactic | Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.\\n\\nThere are many ways an adversary may hijack the flow of execution, including by manipulating how the operating system locates programs to be executed. How the operating system locates libraries to be used by a program can also be intercepted. Locations where the operating system looks for programs/resources, such as file directories and in the case of Windows the Registry, could also be poisoned to include malicious payloads.\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"mitre-attack-pattern\"}], \"labels\": [\"misp:galaxy-name=\\\"Attack Pattern\\\"\", \"misp:galaxy-type=\\\"mitre-attack-pattern\\\"\", \"misp-galaxy:mitre-attack-pattern=\\\"Hijack Execution Flow - T1574\\\"\"], \"external_references\": [{\"source_name\": \"mitre-attack\", \"external_id\": \"T1574\"}]}, {\"type\": \"attack-pattern\", \"id\": \"attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"Ingress Tool Transfer - T1105\", \"description\": \"ATT&CK Tactic | Adversaries may transfer tools or other files from an external system into a compromised environment. Tools or files may be copied from an external adversary-controlled system to the victim network through the command and control channel or through alternate protocols such as [ftp](https://attack.mitre.org/software/S0095). Once present, adversaries may also transfer/spread tools between victim devices within a compromised environment (i.e. [Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570)). \\n\\nFiles can also be transferred using various [Web Service](https://attack.mitre.org/techniques/T1102)s as well as native or otherwise present tools on the victim system.(Citation: PTSecurity Cobalt Dec 2016)\\n\\nOn Windows, adversaries may use various utilities to download tools, such as `copy`, `finger`, and [PowerShell](https://attack.mitre.org/techniques/T1059/001) commands such as <code>IEX(New-Object Net.WebClient).downloadString()</code> and <code>Invoke-WebRequest</code>. On Linux and macOS systems, a variety of utilities also exist, such as `curl`, `scp`, `sftp`, `tftp`, `rsync`, `finger`, and `wget`.(Citation: t1105_lolbas)\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"mitre-attack-pattern\"}], \"labels\": [\"misp:galaxy-name=\\\"Attack Pattern\\\"\", \"misp:galaxy-type=\\\"mitre-attack-pattern\\\"\", \"misp-galaxy:mitre-attack-pattern=\\\"Ingress Tool Transfer - T1105\\\"\"], \"external_references\": [{\"source_name\": \"mitre-attack\", \"external_id\": \"T1105\"}]}, {\"type\": \"attack-pattern\", \"id\": \"attack-pattern--82caa33e-d11a-433a-94ea-9b5a5fbef81d\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"Virtualization/Sandbox Evasion - T1497\", \"description\": \"ATT&CK Tactic | Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497) during automated discovery to shape follow-on behaviors.(Citation: Deloitte Environment Awareness)\\n\\nAdversaries may use several methods to accomplish [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497) such as checking for security monitoring tools (e.g., Sysinternals, Wireshark, etc.) or other system artifacts associated with analysis or virtualization. Adversaries may also check for legitimate user activity to help determine if it is in an analysis environment. Additional methods include use of sleep timers or loops within malware code to avoid operating within a temporary sandbox.(Citation: Unit 42 Pirpi July 2015)\\n\\n\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"mitre-attack-pattern\"}], \"labels\": [\"misp:galaxy-name=\\\"Attack Pattern\\\"\", \"misp:galaxy-type=\\\"mitre-attack-pattern\\\"\", \"misp-galaxy:mitre-attack-pattern=\\\"Virtualization/Sandbox Evasion - T1497\\\"\"], \"external_references\": [{\"source_name\": \"mitre-attack\", \"external_id\": \"T1497\"}]}, {\"type\": \"attack-pattern\", \"id\": \"attack-pattern--391d824f-0ef1-47a0-b0ee-c59a75e27670\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"Native API - T1106\", \"description\": \"ATT&CK Tactic | Adversaries may interact with the native OS application programming interface (API) to execute behaviors. Native APIs provide a controlled means of calling low-level OS services within the kernel, such as those involving hardware/devices, memory, and processes.(Citation: NT API Windows)(Citation: Linux Kernel API) These native APIs are leveraged by the OS during system boot (when other system components are not yet initialized) as well as carrying out tasks and requests during routine operations.\\n\\nNative API functions (such as <code>NtCreateProcess</code>) may be directed invoked via system calls / syscalls, but these features are also often exposed to user-mode applications via interfaces and libraries.(Citation: OutFlank System Calls)(Citation: CyberBit System Calls)(Citation: MDSec System Calls) For example, functions such as the Windows API <code>CreateProcess()</code> or GNU <code>fork()</code> will allow programs and scripts to start other processes.(Citation: Microsoft CreateProcess)(Citation: GNU Fork) This may allow API callers to execute a binary, run a CLI command, load modules, etc. as thousands of similar API functions exist for various system operations.(Citation: Microsoft Win32)(Citation: LIBC)(Citation: GLIBC)\\n\\nHigher level software frameworks, such as Microsoft .NET and macOS Cocoa, are also available to interact with native APIs. These frameworks typically provide language wrappers/abstractions to API functionalities and are designed for ease-of-use/portability of code.(Citation: Microsoft NET)(Citation: Apple Core Services)(Citation: MACOS Cocoa)(Citation: macOS Foundation)\\n\\nAdversaries may abuse these OS API functions as a means of executing behaviors. Similar to [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059), the native API and its hierarchy of interfaces provide mechanisms to interact with and utilize various components of a victimized system. While invoking API functions, adversaries may also attempt to bypass defensive tools (ex: unhooking monitored functions via [Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001)).\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"mitre-attack-pattern\"}], \"labels\": [\"misp:galaxy-name=\\\"Attack Pattern\\\"\", \"misp:galaxy-type=\\\"mitre-attack-pattern\\\"\", \"misp-galaxy:mitre-attack-pattern=\\\"Native API - T1106\\\"\"], \"external_references\": [{\"source_name\": \"mitre-attack\", \"external_id\": \"T1106\"}]}, {\"type\": \"attack-pattern\", \"id\": \"attack-pattern--b83e166d-13d7-4b52-8677-dff90c548fd7\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"Subvert Trust Controls - T1553\", \"description\": \"ATT&CK Tactic | Adversaries may undermine security controls that will either warn users of untrusted activity or prevent execution of untrusted programs. Operating systems and security products may contain mechanisms to identify programs or websites as possessing some level of trust. Examples of such features would include a program being allowed to run because it is signed by a valid code signing certificate, a program prompting the user with a warning because it has an attribute set from being downloaded from the Internet, or getting an indication that you are about to connect to an untrusted site.\\n\\nAdversaries may attempt to subvert these trust mechanisms. The method adversaries use will depend on the specific mechanism they seek to subvert. Adversaries may conduct [File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222) or [Modify Registry](https://attack.mitre.org/techniques/T1112) in support of subverting these controls.(Citation: SpectorOps Subverting Trust Sept 2017) Adversaries may also create or steal code signing certificates to acquire trust on target systems.(Citation: Securelist Digital Certificates)(Citation: Symantec Digital Certificates) \", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"mitre-attack-pattern\"}], \"labels\": [\"misp:galaxy-name=\\\"Attack Pattern\\\"\", \"misp:galaxy-type=\\\"mitre-attack-pattern\\\"\", \"misp-galaxy:mitre-attack-pattern=\\\"Subvert Trust Controls - T1553\\\"\"], \"external_references\": [{\"source_name\": \"mitre-attack\", \"external_id\": \"T1553\"}]}, {\"type\": \"attack-pattern\", \"id\": \"attack-pattern--106c0cf6-bf73-4601-9aa8-0945c2715ec5\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"Create or Modify System Process - T1543\", \"description\": \"ATT&CK Tactic | Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence. When operating systems boot up, they can start processes that perform background system functions. On Windows and Linux, these system processes are referred to as services.(Citation: TechNet Services) On macOS, launchd processes known as [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) and [Launch Agent](https://attack.mitre.org/techniques/T1543/001) are run to finish system initialization and load user specific parameters.(Citation: AppleDocs Launch Agent Daemons) \\n\\nAdversaries may install new services, daemons, or agents that can be configured to execute at startup or a repeatable interval in order to establish persistence. Similarly, adversaries may modify existing services, daemons, or agents to achieve the same effect.  \\n\\nServices, daemons, or agents may be created with administrator privileges but executed under root/SYSTEM privileges. Adversaries may leverage this functionality to create or modify system processes in order to escalate privileges.(Citation: OSX Malware Detection)  \", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"mitre-attack-pattern\"}], \"labels\": [\"misp:galaxy-name=\\\"Attack Pattern\\\"\", \"misp:galaxy-type=\\\"mitre-attack-pattern\\\"\", \"misp-galaxy:mitre-attack-pattern=\\\"Create or Modify System Process - T1543\\\"\"], \"external_references\": [{\"source_name\": \"mitre-attack\", \"external_id\": \"T1543\"}]}, {\"type\": \"attack-pattern\", \"id\": \"attack-pattern--42e8de7b-37b2-4258-905a-6897815e58e0\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"Masquerading - T1036\", \"description\": \"ATT&CK Tactic | Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools. Masquerading occurs when the name or location of an object, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation. This may include manipulating file metadata, tricking users into misidentifying the file type, and giving legitimate task or service names.\\n\\nRenaming abusable system utilities to evade security monitoring is also a form of [Masquerading](https://attack.mitre.org/techniques/T1036).(Citation: LOLBAS Main Site)\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"mitre-attack-pattern\"}], \"labels\": [\"misp:galaxy-name=\\\"Attack Pattern\\\"\", \"misp:galaxy-type=\\\"mitre-attack-pattern\\\"\", \"misp-galaxy:mitre-attack-pattern=\\\"Masquerading - T1036\\\"\"], \"external_references\": [{\"source_name\": \"capec\", \"external_id\": \"CAPEC-177\"}]}, {\"type\": \"attack-pattern\", \"id\": \"attack-pattern--799ace7f-e227-4411-baa0-8868704f2a69\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"Indicator Removal on Host - T1070\", \"description\": \"ATT&CK Tactic | Adversaries may delete or modify artifacts generated on a host system to remove evidence of their presence or hinder defenses. Various artifacts may be created by an adversary or something that can be attributed to an adversary\\u2019s actions. Typically these artifacts are used as defensive indicators related to monitored events, such as strings from downloaded files, logs that are generated from user actions, and other data analyzed by defenders. Location, format, and type of artifact (such as command or login history) are often specific to each platform.\\n\\nRemoval of these indicators may interfere with event collection, reporting, or other processes used to detect intrusion activity. This may compromise the integrity of security solutions by causing notable events to go unreported. This activity may also impede forensic analysis and incident response, due to lack of sufficient data to determine what occurred.\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"mitre-attack-pattern\"}], \"labels\": [\"misp:galaxy-name=\\\"Attack Pattern\\\"\", \"misp:galaxy-type=\\\"mitre-attack-pattern\\\"\", \"misp-galaxy:mitre-attack-pattern=\\\"Indicator Removal on Host - T1070\\\"\"], \"external_references\": [{\"source_name\": \"capec\", \"external_id\": \"CAPEC-93\"}]}, {\"type\": \"attack-pattern\", \"id\": \"attack-pattern--54a649ff-439a-41a4-9856-8d144a2551ba\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"Remote Services - T1021\", \"description\": \"ATT&CK Tactic | Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into a service specifically designed to accept remote connections, such as telnet, SSH, and VNC. The adversary may then perform actions as the logged-on user.\\n\\nIn an enterprise environment, servers and workstations can be organized into domains. Domains provide centralized identity management, allowing users to login using one set of credentials across the entire network. If an adversary is able to obtain a set of valid domain credentials, they could login to many different machines using remote access protocols such as secure shell (SSH) or remote desktop protocol (RDP).(Citation: SSH Secure Shell)(Citation: TechNet Remote Desktop Services)\\n\\nLegitimate applications (such as [Software Deployment Tools](https://attack.mitre.org/techniques/T1072) and other administrative programs) may utilize [Remote Services](https://attack.mitre.org/techniques/T1021) to access remote hosts. For example, Apple Remote Desktop (ARD) on macOS is native software used for remote management. ARD leverages a blend of protocols, including [VNC](https://attack.mitre.org/techniques/T1021/005) to send the screen and control buffers and [SSH](https://attack.mitre.org/techniques/T1021/004) for secure file transfer.(Citation: Remote Management MDM macOS)(Citation: Kickstart Apple Remote Desktop commands)(Citation: Apple Remote Desktop Admin Guide 3.3) Adversaries can abuse applications such as ARD to gain remote code execution and perform lateral movement. In versions of macOS prior to 10.14, an adversary can escalate an SSH session to an ARD session which enables an adversary to accept TCC (Transparency, Consent, and Control) prompts without user interaction and gain access to data.(Citation: FireEye 2019 Apple Remote Desktop)(Citation: Lockboxx ARD 2019)(Citation: Kickstart Apple Remote Desktop commands)\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"mitre-attack-pattern\"}], \"labels\": [\"misp:galaxy-name=\\\"Attack Pattern\\\"\", \"misp:galaxy-type=\\\"mitre-attack-pattern\\\"\", \"misp-galaxy:mitre-attack-pattern=\\\"Remote Services - T1021\\\"\"], \"external_references\": [{\"source_name\": \"capec\", \"external_id\": \"CAPEC-555\"}]}, {\"type\": \"attack-pattern\", \"id\": \"attack-pattern--4061e78c-1284-44b4-9116-73e4ac3912f7\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"Remote Access Tools - T1219\", \"description\": \"ATT&CK Tactic | An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks. These services are commonly used as legitimate technical support software, and may be whitelisted within a target environment. Remote access tools like VNC, Ammy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)\\n\\nRemote access tools may be established and used post-compromise as alternate communications channel for [Redundant Access](https://attack.mitre.org/techniques/T1108) or as a way to establish an interactive remote desktop session with the target system. They may also be used as a component of malware to establish a reverse connection or back-connect to a service or adversary controlled system.\\n\\nAdmin tools such as TeamViewer have been used by several groups targeting institutions in countries of interest to the Russian state and criminal campaigns. (Citation: CrowdStrike 2015 Global Threat Report) (Citation: CrySyS Blog TeamSpy)\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"mitre-attack-pattern\"}], \"labels\": [\"misp:galaxy-name=\\\"Attack Pattern\\\"\", \"misp:galaxy-type=\\\"mitre-attack-pattern\\\"\", \"misp-galaxy:mitre-attack-pattern=\\\"Remote Access Tools - T1219\\\"\"], \"external_references\": [{\"source_name\": \"mitre-attack\", \"external_id\": \"T1219\"}]}, {\"type\": \"attack-pattern\", \"id\": \"attack-pattern--a8c31121-852b-46bd-9ba4-674ae5afe7ad\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"Input Capture - T1417\", \"description\": \"ATT&CK Tactic | Adversaries may capture user input to obtain credentials or other information from the user through various methods.\\n\\nMalware may masquerade as a legitimate third-party keyboard to record user keystrokes.(Citation: Zeltser-Keyboard) On both Android and iOS, users must explicitly authorize the use of third-party keyboard apps. Users should be advised to use extreme caution before granting this authorization when it is requested.\\n\\nOn Android, malware may abuse accessibility features to record keystrokes by registering an `AccessibilityService` class, overriding the `onAccessibilityEvent` method, and listening for the `AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED` event type. The event object passed into the function will contain the data that the user typed.\\n\\nAdditional methods of keylogging may be possible if root access is available.\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"mitre-attack-pattern\"}], \"labels\": [\"misp:galaxy-name=\\\"Attack Pattern\\\"\", \"misp:galaxy-type=\\\"mitre-attack-pattern\\\"\", \"misp-galaxy:mitre-attack-pattern=\\\"Input Capture - T1417\\\"\"], \"external_references\": [{\"source_name\": \"mitre-attack\", \"external_id\": \"T1417\"}]}, {\"type\": \"attack-pattern\", \"id\": \"attack-pattern--e4dc8c01-417f-458d-9ee0-bb0617c1b391\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"Debugger Evasion - T1622\", \"description\": \"ATT&CK Tactic | Adversaries may employ various means to detect and avoid debuggers. Debuggers are typically used by defenders to trace and/or analyze the execution of potential malware payloads.(Citation: ProcessHacker Github)\\n\\nDebugger evasion may include changing behaviors based on the results of the checks for the presence of artifacts indicative of a debugged environment. Similar to [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497), if the adversary detects a debugger, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for debugger artifacts before dropping secondary or additional payloads.\\n\\nSpecific checks will vary based on the target and/or adversary, but may involve [Native API](https://attack.mitre.org/techniques/T1106) function calls such as <code>IsDebuggerPresent()</code> and <code> NtQueryInformationProcess()</code>, or manually checking the <code>BeingDebugged</code> flag of the Process Environment Block (PEB). Other checks for debugging artifacts may also seek to enumerate hardware breakpoints, interrupt assembly opcodes, time checks, or measurements if exceptions are raised in the current process (assuming a present debugger would \\u201cswallow\\u201d or handle the potential error).(Citation: hasherezade debug)(Citation: AlKhaser Debug)(Citation: vxunderground debug)\\n\\nAdversaries may use the information learned from these debugger checks during automated discovery to shape follow-on behaviors. Debuggers can also be evaded by detaching the process or flooding debug logs with meaningless data via messages produced by looping [Native API](https://attack.mitre.org/techniques/T1106) function calls such as <code>OutputDebugStringW()</code>.(Citation: wardle evilquest partii)(Citation: Checkpoint Dridex Jan 2021)\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"mitre-attack-pattern\"}], \"labels\": [\"misp:galaxy-name=\\\"Attack Pattern\\\"\", \"misp:galaxy-type=\\\"mitre-attack-pattern\\\"\", \"misp-galaxy:mitre-attack-pattern=\\\"Debugger Evasion - T1622\\\"\"], \"external_references\": [{\"source_name\": \"mitre-attack\", \"external_id\": \"T1622\"}]}, {\"type\": \"attack-pattern\", \"id\": \"attack-pattern--92a78814-b191-47ca-909c-1ccfe3777414\", \"created\": \"2026-04-14T20:53:41.000Z\", \"modified\": \"2026-04-14T20:53:41.000Z\", \"name\": \"Software Deployment Tools - T1072\", \"description\": \"ATT&CK Tactic | Adversaries may gain access to and use third-party software suites installed within an enterprise network, such as administration, monitoring, and deployment systems, to move laterally through the network. Third-party applications and software deployment systems may be in use in the network environment for administration purposes (e.g., SCCM, HBSS, Altiris, etc.).\\n\\nAccess to a third-party network-wide or enterprise-wide software system may enable an adversary to have remote code execution on all systems that are connected to such a system. The access may be used to laterally move to other systems, gather information, or cause a specific effect, such as wiping the hard drives on all endpoints.\\n\\nThe permissions required for this action vary by system configuration; local credentials may be sufficient with direct access to the third-party system, or specific domain credentials may be required. However, the system may require an administrative account to log in or to perform it's intended purpose.\", \"kill_chain_phases\": [{\"kill_chain_name\": \"misp-category\", \"phase_name\": \"mitre-attack-pattern\"}], \"labels\": [\"misp:galaxy-name=\\\"Attack Pattern\\\"\", \"misp:galaxy-type=\\\"mitre-attack-pattern\\\"\", \"misp-galaxy:mitre-attack-pattern=\\\"Software Deployment Tools - T1072\\\"\"], \"external_references\": [{\"source_name\": \"capec\", \"external_id\": \"CAPEC-187\"}]}]}"
  }

    result = analyze_cti(test_input)
    print(json.dumps(result, ensure_ascii=False, indent=2))
