#IoC 검증 모듈의 LLM 프롬프트 템플릿.

import json

IOC_VALIDATION_INSTRUCTION = """Validate IoC extraction quality against the source content. You MUST scan the ENTIRE raw_content from start to end before answering - do not skim, sample, or stop early. Output JSON ONLY with 'result' as the FIRST field.

Rule 1: 'result' MUST appear first and contain exactly one of: 'success', 're-extraction', 'removed'.

Rule 2: For EACH ioc_value in the input list, perform an exhaustive search across the COMPLETE raw_content. Check whether it appears as exact substring, AND check whether a similar value (with typos, character mutations) appears.

Rule 3: 'virustotal_result' is a reference signal only and does NOT determine the result by itself. Always verify against raw_content first.

Rule 4: Return 'result': 'success' ONLY when EVERY ioc_value in the input appears as an exact substring somewhere in raw_content. Output the original ioc_list unchanged.

Rule 5: Return 'result': 're-extraction' when at least one ioc_value is incorrect. There are TWO sub-cases:
  Case A (typo): If the wrong value has a similar correct version in raw_content (typo, mutation, missing/extra characters), use feedback format: [CONTENT-ERROR] '<wrong>' should be '<correct>'.
  Case B (mismatch): If the wrong value is NOT in raw_content and no similar value exists either, use feedback format: [MISMATCH] '<value>' (<type>) does not appear in source.
Output the original ioc_list unchanged.

Rule 6: Return 'result': 'removed' ONLY when NONE of the ioc_values appear in raw_content AND no similar values exist for any of them. Output an empty ioc_list (empty array []). No feedback needed.

Rule 7: 'feedback' field is REQUIRED for 're-extraction', and OMITTED for 'success' and 'removed'.

Rule 8: For 're-extraction', combine multiple [CONTENT-ERROR] and [MISMATCH] entries in the feedback if applicable.

Do NOT include any text or explanation outside the JSON object."""


def build_ioc_validation_prompt(
    raw_content: str,
    ioc_list: list[dict],
    virustotal_result: str = "False",
) -> str:
    input_payload = {
        "raw_content": raw_content,
        "ioc_list": ioc_list,
        "virustotal_result": virustotal_result,
    }
    input_json = json.dumps(input_payload, ensure_ascii=False)
    
    return f"""{IOC_VALIDATION_INSTRUCTION}

{input_json}"""