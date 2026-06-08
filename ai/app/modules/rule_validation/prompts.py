#정책 검증 에이전트의 LLM 프롬프트 템플릿.


import json
from typing import Any
from langchain_core.messages import SystemMessage, HumanMessage


RULE_VALIDATION_SYSTEM_PROMPT = """Analyze the security rule for semantic quality issues based on the attack context. Identify weaknesses that pass syntactic/FN/FP validation but reduce real-world effectiveness. Return a JSON object with 'quality_score' (high/medium/low), 'feedback' (single-line string starting with 'quality fail:' or '-' if none), and 'regeneration_needed' (true/false).

Valid rule criteria by IoC type (do NOT flag these as weaknesses):
- url: Matching the domain/host portion alone is sufficient. Do NOT require path comparison. A rule without the URL path is valid and complete.
- hash: A single hash field match (MD5/SHA1/SHA256) is complete. Do NOT require additional field comparisons. A 64-character SHA256 match alone is valid.
- ip: A single IP address match is sufficient.
- domain: A content match on the domain string is sufficient.

Only set regeneration_needed=true for genuine semantic defects (e.g., wrong IoC value, logically broken matching, rule that cannot fire). Do NOT regenerate for missing path, single-field hash, or coverage concerns when the core IoC is correctly matched."""


def build_rule_validation_messages(
    rule_type: str,
    rule_content: str,
    ioc_list: list[dict],
    attack_type: str,
    attack_features: str = "",
) -> list:
    user_payload = {
        "rule_type": rule_type,
        "ioc_list": ioc_list,
        "rule_content": rule_content,
        "attack_type": attack_type,
        "attack_features": attack_features,
    }
    user_content = json.dumps(user_payload, ensure_ascii=False)
    
    return [
        SystemMessage(content=RULE_VALIDATION_SYSTEM_PROMPT),
        HumanMessage(content=user_content),
    ]


def map_quality_to_result(
    quality_score: str,
    regeneration_needed: bool,
    current_retry_count: int,
    max_retry: int = 3,
) -> str:
    if not regeneration_needed:
        return "success"
    
    if current_retry_count >= max_retry:
        return "removed"
    
    return "re-generation"