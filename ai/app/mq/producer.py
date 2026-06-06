#MQ Producer - AI 서버에서 백엔드로 메시지 발행

import json
import logging
import re
from typing import Any

import pika

from app.config import settings
from app.modules.rule_generation.generator import _extract_ioc_value_from_rule


logger = logging.getLogger(__name__)


BACKEND_ATTACK_TYPE_MAP = {
    "web_attack": "WEB_ATTACK",
    "ransomware": "RANSOMWARE",
    "phishing": "PHISHING",
    "ddos": "DDOS",
    "credential_stuffing": "CREDENTIAL_STUFFING",
    "IOC_ONLY": "IOC_ONLY",
    "unknown": "OTHER",
}


def _to_backend_attack_type(attack_type_raw: str) -> str:
    if not attack_type_raw:
        return ""
    return BACKEND_ATTACK_TYPE_MAP.get(attack_type_raw, attack_type_raw.upper())


def _get_connection() -> pika.BlockingConnection:
    params = pika.URLParameters(settings.rabbitmq_url)
    params.heartbeat = 0
    params.blocked_connection_timeout = 600
    return pika.BlockingConnection(params)


def _extract_rule_feedback(combined_feedback: str, rule_index: int) -> str:
    if not combined_feedback:
        return ""
    pattern = rf"룰#{rule_index}:\s*(.*?)(?=\s*\|\s*룰#\d+:|$)"
    match = re.search(pattern, combined_feedback, re.DOTALL)
    if match:
        return match.group(1).strip()
    return combined_feedback


def _extract_agent_feedback(combined: str, rule_type: str, ioc_type: str) -> str:
    if not combined:
        return ""
    pattern = rf"그룹#\d+\({re.escape(rule_type)}/{re.escape(ioc_type)}\):\s*(.*?)(?=\s*\|\|\s*그룹#\d+|$)"
    match = re.search(pattern, combined, re.DOTALL)
    if match:
        return match.group(1).strip()
    return combined


def _uppercase_attack_detail(attack_detail: list) -> list:
    if not attack_detail:
        return []
    result = []
    for item in attack_detail:
        if isinstance(item, dict):
            new_item = dict(item)
            if "attack_type" in new_item and isinstance(new_item["attack_type"], str):
                new_item["attack_type"] = new_item["attack_type"].upper()
            result.append(new_item)
        else:
            result.append(item)
    return result


def _build_ioc_only_response(final_state: dict) -> dict:
    attack_type_raw = final_state.get("attack_type", "") or ""
    attack_detail_list = _uppercase_attack_detail(final_state.get("attack_detail", []))
    return {
        "cti_data_id": final_state.get("cti_data_id"),
        "status": "success",
        "attack_type": _to_backend_attack_type(attack_type_raw),  # → OTHER
        "attack_detail": attack_detail_list[0] if attack_detail_list else {},
        "summary": final_state.get("summary", ""),
        "detection_rule": None,
        "feedback": None,
        "regen_count": 0,
    }


def _resolve_ioc_value(rule_content: str, ioc_type: str, original_ioc_list: list) -> str:
    extracted = _extract_ioc_value_from_rule(rule_content, ioc_type)

    if ioc_type == "url" and extracted:
        for ioc in original_ioc_list or []:
            if ioc.get("ioc_type") == "url" and extracted in ioc.get("ioc_value", ""):
                return ioc.get("ioc_value", "")
    return extracted


def _build_success_responses(final_state: dict) -> list[dict]:
    cti_id = final_state.get("cti_data_id")
    detection_rule_list = final_state.get("detection_rule", [])
    
    grammar_combined = final_state.get("grammar_feedback", "")
    fn_combined = final_state.get("fn_feedback", "")
    fp_combined = final_state.get("fp_feedback", "")
    agent_combined = final_state.get("agent_judgement", "")
    
    grammar_result = final_state.get("grammar_result")
    fn_result = final_state.get("fn_result")
    fp_result = final_state.get("fp_result")
    agent_result = final_state.get("rule_validation_result")
    
    attack_type_raw = final_state.get("attack_type", "") or ""
    attack_type_upper = _to_backend_attack_type(attack_type_raw)
    
    attack_detail_list = _uppercase_attack_detail(final_state.get("attack_detail", []))
    attack_detail_obj = attack_detail_list[0] if attack_detail_list else {}

    original_ioc_list = final_state.get("ioc_list", [])

    common = {
        "cti_data_id": cti_id,
        "status": "success",
        "attack_type": attack_type_upper,
        "attack_detail": "hi",
        "summary": final_state.get("summary", ""),
    }
    
    messages = []
    for i, rule in enumerate(detection_rule_list):
        rule_type = rule.get("rule_type", "")
        ioc_type = rule.get("ioc_type", "")
        rule_content = rule.get("rule_content", "")
        
        ioc_value = _resolve_ioc_value(rule_content, ioc_type, original_ioc_list)
        
        rule_entry = {
            "rule_type": rule_type.upper(),
            "ioc_type": ioc_type.upper(),
            "ioc_value": ioc_value,
            "rule_content": rule_content,
        }
        
        rule_index = i + 1
        rule_feedback = {
                "grammar_result": grammar_result,
                "grammar_feedback": _extract_rule_feedback(grammar_combined, rule_index),
                "fn_result": fn_result,
                "fn_feedback": _extract_rule_feedback(fn_combined, rule_index),
                "fp_result": fp_result,
                "fp_feedback": _extract_rule_feedback(fp_combined, rule_index),
                "agent_result": agent_result,
                "agent_feedback": _extract_agent_feedback(agent_combined, rule_type, ioc_type),
            }

        
        msg = {
            **common,
            "detection_rule": rule_entry,
            "feedback": rule_feedback,
            "regen_count": final_state.get("regen_count", 0),
        }
        messages.append(msg)
    
    return messages


def _build_removed_response(final_state: dict) -> dict:
    return {
        "cti_data_id": final_state.get("cti_data_id"),
        "status": "removed",
    }


def _build_error_response(cti_data_id: int, error_message: str) -> dict:
    return {
        "cti_data_id": cti_data_id,
        "status": "removed",
    }


def send_response_to_backend(final_state: dict) -> None:
    status = final_state.get("status", "removed")
    cti_id = final_state.get("cti_data_id")
    
    if status == "success":
        detection_rule_list = final_state.get("detection_rule", [])
        if not detection_rule_list:
            response = _build_ioc_only_response(final_state)
            _publish_message(
                queue_name=settings.mq_response_queue,
                message=response,
            )
            logger.info(
                f"[MQ Producer] 룰 없음(OTHER) 응답 발행: cti_id={cti_id}, "
                f"queue={settings.mq_response_queue}"
            )
            return
            
        responses = _build_success_responses(final_state)
        for response in responses:
            _publish_message(
                queue_name=settings.mq_response_queue,
                message=response,
            )
        logger.info(
            f"[MQ Producer] 응답 발행 완료: cti_id={cti_id}, "
            f"status=success, 메시지 {len(responses)}개, queue={settings.mq_response_queue}"
        )
    else:
        response = _build_removed_response(final_state)
        _publish_message(
            queue_name=settings.mq_response_queue,
            message=response,
        )
        logger.info(
            f"[MQ Producer] 응답 발행 완료: cti_id={cti_id}, "
            f"status=removed, queue={settings.mq_response_queue}"
        )


def send_error_to_backend(cti_data_id: int, error_message: str) -> None:
    response = _build_error_response(cti_data_id, error_message)
    
    _publish_message(
        queue_name=settings.mq_response_queue,
        message=response,
    )
    
    logger.error(
        f"[MQ Producer] 에러 응답 발행(removed로 통일): cti_id={cti_data_id}, "
        f"message={error_message}"
    )


def _publish_message(queue_name: str, message: dict) -> None:
    connection = None
    try:
        connection = _get_connection()
        channel = connection.channel()
        
        channel.queue_declare(queue=queue_name, durable=True)
        
        body = json.dumps(message, ensure_ascii=False).encode("utf-8")
        
        channel.basic_publish(
            exchange="",
            routing_key=queue_name,
            body=body,
            properties=pika.BasicProperties(
                content_type="application/json",
                delivery_mode=2,
            ),
        )
    
    except Exception as e:
        logger.error(f"[MQ Producer] 메시지 발행 실패: {type(e).__name__}: {e}")
        raise
    
    finally:
        if connection and not connection.is_closed:
            connection.close()