#LangGraph 노드 함수들.
import re
import logging
from typing import Any

from app.graph.state import AgentState
from app.modules.cti_analysis.analyzer import analyze_cti
from app.modules.ioc_verification.validator import (
    validate_iocs,
    IoCValidationError,
)
from app.modules.rule_generation.generator import (
    generate_rules,
    resolve_snort_sid_start,
    RuleGenerationError,
)
from app.modules.rule_validation.three_stage_validator import (
    run_three_stage_validation,
    ThreeStageValidationError,
)
from app.modules.rule_validation.agent import (
    judge_validation_result,
    ValidationAgentError,
)


logger = logging.getLogger(__name__)


def cti_analysis_node(state: AgentState) -> dict[str, Any]:
    logger.info(f"[cti_analysis] CTI ID={state.get('cti_data_id')} 분석 시작")
    
    raw_content = state.get("raw_content", "")
    platform_id = state.get("platform_id", 0)
    
    input_payload = {
        "platform_id": platform_id,
        "raw_content": raw_content,
    }
    
    try:
        result = analyze_cti(input_payload)
    except Exception as e:
        logger.error(f"[cti_analysis] 예외 발생: {e}")
        return {
            "status": "removed",
            "error_message": f"CTI 분석 예외: {e}",
            "error_node": "cti_analysis",
        }
    
    if "error" in result and result["error"]:
        logger.error(
            f"[cti_analysis] 비즈니스 오류: {result.get('error')} - {result.get('message')}"
        )
        return {
            "status": "removed",
            "error_message": result.get("message", "CTI 분석 실패"),
            "error_node": "cti_analysis",
        }
    
    raw_attack_type = result.get("attack_type", "other")
    attack_type_mapping = {
        "web_attack": "web_attack",
        "ransomware": "ransomware",
        "phishing": "phishing",
        "ddos": "ddos",
        "credential_stuffing": "credential_stuffing",
        "unknown": "other",
        "IOC_ONLY": "IOC_ONLY",
    }
    attack_type = attack_type_mapping.get(raw_attack_type, "other")
    is_ioc_only = raw_attack_type == "IOC_ONLY"

    ioc_list = result.get("ioc_list") or []

    attack_detail = result.get("attack_detail", [])
    if is_ioc_only:
        attack_detail = []

    logger.info(
        f"[cti_analysis] 완료: raw_attack_type={raw_attack_type}, "
        f"mapped={attack_type}, is_ioc_only={is_ioc_only}, ioc_count={len(ioc_list)}"
    )

    return {
        "raw_attack_type": raw_attack_type,
        "is_ioc_only": is_ioc_only,
        "attack_type": attack_type,
        "attack_detail": attack_detail,
        "summary": result.get("summary", ""),
        "ioc_list": ioc_list,
    }


def ioc_verification_node(state: AgentState) -> dict[str, Any]:
    logger.info(f"[ioc_verification] CTI ID={state.get('cti_data_id')} 검증 시작")
    
    raw_content = state.get("raw_content", "")
    ioc_list = state.get("ioc_list", [])
    
    try:
        result = validate_iocs(raw_content=raw_content, ioc_list=ioc_list)
        
        logger.info(
            f"[ioc_verification] 완료: result={result['result']}, "
            f"vt={result['virustotal_result']}"
        )
        
        retry_count = state.get("cti_analysis_retry", 0)
        if result["result"] == "re-extraction":
            retry_count += 1
        
        return {
            "virustotal_result": result["virustotal_result"],
            "ioc_list": result["ioc_list"],
            "ioc_verification_result": result["result"],
            "ioc_feedback": result["feedback"],
            "cti_analysis_retry": retry_count,
        }
    
    except IoCValidationError as e:
        logger.error(f"[ioc_verification] 비즈니스 오류: {e}")
        return {
            "status": "removed",
            "error_message": str(e),
            "error_node": "ioc_verification",
        }


def mark_ioc_only_node(state: AgentState) -> dict:
    logger.info(
        f"[mark_ioc_only] attack_type={state.get('attack_type')} "
        f"→ 룰 없이 백엔드 전송 준비 (백엔드엔 OTHER)"
    )
    return {
        "status": "success",
        "detection_rule": [],
    }


def rule_generation_node(state: AgentState) -> dict[str, Any]:
    logger.info(f"[rule_generation] CTI ID={state.get('cti_data_id')} 룰 생성 시작")
    
    retry_count = state.get("rule_generation_retry", 0)
    if retry_count > 0:
        logger.info("=" * 70)
        logger.info(f"[rule_generation] ⚠️ 재생성 #{retry_count}")
        logger.info(f"  이전 룰: {len(state.get('detection_rule', []))}개")
        logger.info(f"  재생성 원인:")
        logger.info(f"    Grammar: {state.get('grammar_result')} - {state.get('grammar_feedback', '')[:200]}")
        logger.info(f"    FN:      {state.get('fn_result')} - {state.get('fn_feedback', '')[:200]}")
        logger.info(f"    FP:      {state.get('fp_result')} - {state.get('fp_feedback', '')[:200]}")
        logger.info(f"    sLLM 판단: {state.get('agent_judgement', '')[:300]}")
        logger.info("=" * 70)

    attack_type = state.get("attack_type", "other")
    ioc_list = state.get("ioc_list", [])
    snort_sid_start = resolve_snort_sid_start(state.get("sid"))
    is_ioc_only = bool(state.get("is_ioc_only", False))

    previous_attempt = ""
    feedback = ""
    if state.get("rule_validation_result") == "re-generation":

        prev_rules = state.get("detection_rule", [])
        if prev_rules:
            previous_attempt = prev_rules[0].get("rule_content", "")
        feedback = state.get("agent_judgement", "")

    try:
        result = generate_rules(
            attack_type=attack_type,
            ioc_list=ioc_list,
            previous_attempt=previous_attempt,
            feedback=feedback,
            base_sid=snort_sid_start,
            is_ioc_only=is_ioc_only,
        )

        detection_rule = result.get("detection_rule", [])
        logger.info(
            f"[rule_generation] 완료: 생성된 룰 {len(detection_rule)}개, "
            f"snort sid 시작={snort_sid_start} (백엔드 sid={state.get('sid')})"
        )

        retry_count = state.get("rule_generation_retry", 0)
        if previous_attempt:
            retry_count += 1

        return {
            "detection_rule": detection_rule,
            "rule_generation_retry": retry_count,
            "regen_count": retry_count,
        }

    except RuleGenerationError as e:
        logger.error(f"[rule_generation] 비즈니스 오류: {e}")
        return {
            "status": "removed",
            "error_message": str(e),
            "error_node": "rule_generation",
        }


def three_stage_validation_node(state: AgentState) -> dict[str, Any]:
    cti_id = state.get('cti_data_id')
    logger.info(f"[three_stage] CTI ID={cti_id} 3단계 검증 시작")
    
    detection_rule = state.get("detection_rule", [])
    if not detection_rule:
        return {
            "status": "removed",
            "error_message": "검증할 detection_rule이 없음",
            "error_node": "three_stage_validation",
        }
    
    all_ioc_list = state.get("ioc_list", [])
    
    logger.info(f"[three_stage] === 검증 대상 ===")
    logger.info(f"  룰 {len(detection_rule)}개, IoC {len(all_ioc_list)}개")
    for i, rule in enumerate(detection_rule):
        logger.info(f"  룰 #{i+1}: type={rule.get('rule_type')}, ioc_type={rule.get('ioc_type')}, content={rule.get('rule_content', '')[:100]}")
    
    grammar_results = []
    fn_results = []
    fp_results = []
    grammar_feedbacks = []
    fn_feedbacks = []
    fp_feedbacks = []

    yara_fn_failure_detected = False
    
    for i, rule in enumerate(detection_rule):
        rule_type = rule.get("rule_type", "")
        rule_content = rule.get("rule_content", "")
        rule_ioc_type = rule.get("ioc_type", "")
        
        filtered_ioc_list = [
            ioc for ioc in all_ioc_list 
            if ioc.get("ioc_type") == rule_ioc_type
        ]
        
        logger.info(f"[three_stage] === 룰 #{i+1}/{len(detection_rule)} 검증 ===")
        logger.info(f"  type={rule_type}, ioc_type={rule_ioc_type}, filtered_iocs={len(filtered_ioc_list)}")
        
        try:
            result = run_three_stage_validation(
                rule_type=rule_type,
                rule_content=rule_content,
                ioc_list=filtered_ioc_list,
            )
            
            grammar_results.append(result.get("grammar_result"))
            fn_results.append(result.get("fn_result"))
            fp_results.append(result.get("fp_result"))
            
            grammar_feedbacks.append(f"룰#{i+1}: {result.get('grammar_feedback', '-')}")
            fn_feedbacks.append(f"룰#{i+1}: {result.get('fn_feedback', '-')}")
            fp_feedbacks.append(f"룰#{i+1}: {result.get('fp_feedback', '-')}")
            
            if rule_type == "yara" and result.get("fn_result") == "failure":
                fn_fb = result.get("fn_feedback", "").lower()
                if "downloaded sample not detected" in fn_fb:
                    logger.info(f"[three_stage] 룰 #{i+1} yara FN failure (룰 문제) → 재생성 흐름")
                else:
                    yara_fn_failure_detected = True
                    logger.info(f"[three_stage] 룰 #{i+1} yara FN failure (환경 문제) → removed")
                    logger.info(
                        f"[three_stage] 룰 #{i+1} yara FN failure 감지 "
                        f"→ 재생성 스킵, removed 처리"
                    )

            logger.info(
                f"[three_stage] 룰 #{i+1} 결과: "
                f"grammar={result.get('grammar_result')}, "
                f"fn={result.get('fn_result')}, "
                f"fp={result.get('fp_result')}"
            )
        
        except Exception as e:
            logger.error(f"[three_stage] 룰 #{i+1} 예외: {e}")
            grammar_results.append("failure")
            fn_results.append("failure")
            fp_results.append("failure")
            grammar_feedbacks.append(f"룰#{i+1}: 예외 - {str(e)}")
            fn_feedbacks.append(f"룰#{i+1}: 예외 - {str(e)}")
            fp_feedbacks.append(f"룰#{i+1}: 예외 - {str(e)}")
    
    def _aggregate(results: list) -> str:
        return "success" if all(r == "success" for r in results) else "failure"
    
    final_result = {
        "grammar_result": _aggregate(grammar_results),
        "grammar_feedback": " | ".join(grammar_feedbacks),
        "fn_result": _aggregate(fn_results),
        "fn_feedback": " | ".join(fn_feedbacks),
        "fp_result": _aggregate(fp_results),
        "fp_feedback": " | ".join(fp_feedbacks),
    }
    
    if yara_fn_failure_detected:
        final_result["status"] = "removed"
        final_result["error_message"] = "yara FN validation failed (재생성 스킵)"
        final_result["error_node"] = "three_stage_validation"
    
    logger.info(f"[three_stage] === 최종 종합 결과 ===")
    logger.info(f"  Grammar: {final_result['grammar_result']}")
    logger.info(f"  FN: {final_result['fn_result']}")
    logger.info(f"  FP: {final_result['fp_result']}")
    
    return final_result


def validation_agent_node(state: AgentState) -> dict[str, Any]:
    if state.get("status"):
        logger.info(f"[validation_agent] 이미 status={state.get('status')} → sLLM 호출 스킵")
        return {
            "rule_validation_result": "skipped",
            "agent_judgement": "three_stage에서 종료 결정 → sLLM 호출 스킵",
        }

    cti_id = state.get('cti_data_id')
    logger.info(f"[validation_agent] CTI ID={cti_id} 판단 시작")
    
    detection_rule = state.get("detection_rule", [])
    if not detection_rule:
        return {
            "status": "removed",
            "error_message": "판단할 detection_rule이 없음",
            "error_node": "validation_agent",
        }
    
    all_ioc_list = state.get("ioc_list", [])
    current_retry = state.get("rule_generation_retry", 0)
    
    three_stage_result = {
        "grammar_result": state.get("grammar_result"),
        "grammar_feedback": state.get("grammar_feedback"),
        "fn_result": state.get("fn_result"),
        "fn_feedback": state.get("fn_feedback"),
        "fp_result": state.get("fp_result"),
        "fp_feedback": state.get("fp_feedback"),
    }
    
    rule_groups = _group_rules_for_validation(detection_rule)
    
    logger.info(f"[validation_agent] 룰 그룹 {len(rule_groups)}개로 검증 시작")
    
    all_results = []
    all_feedbacks = []
    
    for i, group in enumerate(rule_groups):
        rule_type = group["rule_type"]
        rule_content = "\n".join([r.get("rule_content", "") for r in group["rules"]])
        rule_ioc_type = group["ioc_type"]
        
        rule_content_for_sllm = rule_content.replace("CTINK", "ARGOS")
        rule_content_for_sllm = re.sub(r"(->\s*\S+\s+)\d+(\s*\()", r"\1any\2", rule_content_for_sllm)
        
        filtered_ioc_list = [
            ioc for ioc in all_ioc_list 
            if ioc.get("ioc_type") == rule_ioc_type
        ]
        
        logger.info(
            f"[validation_agent] 그룹 #{i+1}/{len(rule_groups)}: "
            f"type={rule_type}, ioc_type={rule_ioc_type}, "
            f"룰 {len(group['rules'])}개, IoC {len(filtered_ioc_list)}개"
        )
        
        try:
            result = judge_validation_result(
                rule_type=rule_type,
                rule_content=rule_content_for_sllm,
                ioc_list=filtered_ioc_list,
                attack_type=state.get("attack_type", ""),
                three_stage_result=three_stage_result,
                attack_detail=state.get("attack_detail", []),
                current_retry_count=current_retry,
                max_retry=3,
            )
            
            all_results.append(result["result"])
            all_feedbacks.append(
                f"그룹#{i+1}({rule_type}/{rule_ioc_type}): {result.get('feedback', '')}"
            )
            
            logger.info(
                f"[validation_agent] 그룹 #{i+1} 결과: {result['result']}"
            )
        
        except Exception as e:
            logger.error(f"[validation_agent] 그룹 #{i+1} 예외: {e}")
            all_results.append("re-generation")
            all_feedbacks.append(f"그룹#{i+1}: 예외 - {str(e)}")
    
    if all(r == "success" for r in all_results):
        final_result = "success"
    elif any(r == "removed" for r in all_results):
        final_result = "removed"
    else:
        final_result = "re-generation"
    
    final_feedback = " || ".join(all_feedbacks)
    
    logger.info(f"[validation_agent] === 최종 종합 결과 ===")
    logger.info(f"  result: {final_result}")
    
    if final_result == "re-generation":
        logger.info("─" * 70)
        logger.info(f"[validation_agent] 🔄 재생성 결정")
        logger.info(f"  피드백: {final_feedback}")
        logger.info(f"  재시도: {current_retry}")
        logger.info("─" * 70)
    elif final_result == "removed":
        logger.info("─" * 70)
        logger.info(f"[validation_agent] ❌ 폐기 결정")
        logger.info(f"  피드백: {final_feedback}")
        logger.info("─" * 70)
    
    update = {
        "rule_validation_result": final_result,
        "agent_judgement": final_feedback,
    }
    
    if final_result == "success":
        update["status"] = "success"
    elif final_result == "removed":
        update["status"] = "removed"
    
    return update


def _group_rules_for_validation(detection_rule: list) -> list:
    groups = []
    yara_buckets = {}
    
    for rule in detection_rule:
        rule_type = rule.get("rule_type", "")
        ioc_type = rule.get("ioc_type", "")
        
        if rule_type == "snort":
            groups.append({
                "rule_type": "snort",
                "ioc_type": ioc_type,
                "rules": [rule],
            })
        elif rule_type == "yara":
            content = rule.get("rule_content", "")
            match = re.search(r'hash\.sha256\([^)]+\)\s*==\s*"([^"]+)"', content)
            hash_value = match.group(1) if match else f"unknown_{len(yara_buckets)}"
            
            if hash_value not in yara_buckets:
                yara_buckets[hash_value] = {
                    "rule_type": "yara",
                    "ioc_type": ioc_type,
                    "rules": [],
                }
            yara_buckets[hash_value]["rules"].append(rule)
    
    groups.extend(yara_buckets.values())
    return groups