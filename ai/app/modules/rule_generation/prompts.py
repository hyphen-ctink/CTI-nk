import json
from langchain_core.messages import HumanMessage, SystemMessage


SNORT_RULE_INSTRUCTION = """Generate Snort rules in JSON format ONLY for network IoCs (ip, domain, url) in this request.
Each rule MUST include sid and rev inside the rule options, e.g. (msg:"..."; content:"..."; sid:1000001; rev:1;).
Rule 1: For 'ip', Snort rule with IP in header and msg containing the IP.
Rule 2: For 'domain', Snort rule with content matching domain.
Rule 3: For 'url', Snort rule with content for host AND uricontent for path.
Rule 4: Generate one Snort rule per IoC. Assign sequential sid starting from base_sid.
Rule 5: msg MUST include the IoC value. Use attack_type in msg as CTINK {ATTACK_TYPE} pattern.
Rule 6: Attack-type hints — phishing port 443; credential_stuffing /login uricontent; ddos threshold.
Rule 7: If previous_attempt and feedback provided, fix rules accordingly.
Output: {"detection_rule": [{"ioc_type","rule_type":"snort","rule_content"}]}"""


YARA_RULE_INSTRUCTION = """Generate YARA rules in JSON format ONLY for hash IoCs.
Rule 1: One hash IoC → exactly ONE rule. Hash comparison is OS-agnostic, so do NOT split into windows/linux. Do NOT include an os_type field.
Rule 2: Use hash.sha256(0, filesize) == "<hash>" in condition when possible.
Rule 3: Generate exactly one rule per hash IoC.
Rule 4: If previous_attempt and feedback provided, fix rules accordingly.
Output: {"detection_rule": [{"ioc_type":"hash","rule_type":"yara","rule_content":"..."}]}"""


def build_snort_rule_generation_messages(
    attack_type: str,
    ioc_list: list[dict],
    base_sid: int,
    previous_attempt: str = "",
    feedback: str = "",
    is_ioc_only: bool = False,
) -> list:
    input_payload = {
        "attack_type": attack_type,
        "ioc_list": ioc_list,
        "base_sid": base_sid,
        "is_ioc_only": is_ioc_only,
    }
    if previous_attempt and feedback:
        input_payload["previous_attempt"] = previous_attempt
        input_payload["feedback"] = feedback

    return [
        SystemMessage(content=SNORT_RULE_INSTRUCTION),
        HumanMessage(content=json.dumps(input_payload, ensure_ascii=False)),
    ]


def build_yara_rule_generation_messages(
    attack_type: str,
    ioc_list: list[dict],
    previous_attempt: str = "",
    feedback: str = "",
    is_ioc_only: bool = False,
) -> list:
    input_payload = {
        "attack_type": attack_type,
        "ioc_list": ioc_list,
        "is_ioc_only": is_ioc_only,
    }
    if previous_attempt and feedback:
        input_payload["previous_attempt"] = previous_attempt
        input_payload["feedback"] = feedback

    return [
        SystemMessage(content=YARA_RULE_INSTRUCTION),
        HumanMessage(content=json.dumps(input_payload, ensure_ascii=False)),
    ]


def build_rule_generation_messages(
    attack_type: str,
    ioc_list: list[dict],
    previous_attempt: str = "",
    feedback: str = "",
) -> list:
    input_payload = {
        "attack_type": attack_type,
        "ioc_list": ioc_list,
    }
    if previous_attempt and feedback:
        input_payload["previous_attempt"] = previous_attempt
        input_payload["feedback"] = feedback

    combined = SNORT_RULE_INSTRUCTION + "\n" + YARA_RULE_INSTRUCTION
    return [
        SystemMessage(content=combined),
        HumanMessage(content=json.dumps(input_payload, ensure_ascii=False)),
    ]
