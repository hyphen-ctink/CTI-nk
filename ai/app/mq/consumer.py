#MQ Consumer - 백엔드로부터 CTI 분석 요청을 받아 LangGraph를 실행

import json
import logging
import sys
import time
from typing import Any

import pika
from pika.exceptions import AMQPConnectionError

from app.config import settings
from app.graph.workflow import get_workflow
from app.mq.producer import send_response_to_backend, send_error_to_backend


logger = logging.getLogger(__name__)

def _process_request(payload: dict) -> dict:
    cti_data_id = payload.get("cti_data_id")
    sid = payload.get("sid")
    platform_id = payload.get("platform_id")
    raw_content = payload.get("raw_content", "")
    
    if not cti_data_id:
        raise ValueError("cti_data_id가 누락되었습니다.")
    if not raw_content or not raw_content.strip():
        raise ValueError("raw_content가 비어 있습니다.")
    
    initial_state = {
        "cti_data_id": cti_data_id,
        "sid": sid,
        "platform_id": platform_id,
        "raw_content": raw_content,
    }
    
    config = {
        "configurable": {
            "thread_id": f"cti_{cti_data_id}",
        }
    }
    
    workflow = get_workflow()
    final_state = workflow.invoke(initial_state, config=config)

    _print_workflow_summary(final_state)
    
    return final_state


def _print_workflow_summary(state: dict) -> None:
    import json
    
    logger.info("=" * 80)
    logger.info(f"워크플로우 최종 결과 - cti_id={state.get('cti_data_id')}")
    logger.info("=" * 80)
    
    logger.info("\n[1] CTI 분석 결과 (Claude)")
    logger.info(f"  attack_type: {state.get('attack_type')}")
    logger.info(f"  summary: {state.get('summary', '')[:200]}")
    logger.info(f"  attack_detail: {state.get('attack_detail', [])}")
    logger.info(f"  ioc_list ({len(state.get('ioc_list', []))}개):")
    for ioc in state.get('ioc_list', []):
        logger.info(f"    - {ioc.get('ioc_type')}: {ioc.get('ioc_value')}")
    
    logger.info("\n[2] IoC 검증 결과 (코드 매칭)")
    logger.info(f"  result: {state.get('ioc_verification_result')}")
    logger.info(f"  virustotal: {state.get('virustotal_result')}")
    logger.info(f"  feedback: {state.get('ioc_feedback', '')}")
    
    detection_rule = state.get('detection_rule', [])
    logger.info(f"\n[3] 생성된 룰 ({len(detection_rule)}개)")
    for i, rule in enumerate(detection_rule):
        logger.info(f"  --- 룰 #{i+1} ---")
        logger.info(f"    rule_type: {rule.get('rule_type')}")
        logger.info(f"    ioc_type: {rule.get('ioc_type')}")
        if rule.get('os_type'):
            logger.info(f"    os_type: {rule.get('os_type')}")
        logger.info(f"    rule_content:")
        for line in rule.get('rule_content', '').split('\n'):
            logger.info(f"      {line}")
    
    logger.info("\n[4] 3단계 검증 결과")
    logger.info(f"  Grammar: {state.get('grammar_result')}")
    logger.info(f"    피드백: {state.get('grammar_feedback', '')[:300]}")
    logger.info(f"  FN:      {state.get('fn_result')}")
    logger.info(f"    피드백: {state.get('fn_feedback', '')[:300]}")
    logger.info(f"  FP:      {state.get('fp_result')}")
    logger.info(f"    피드백: {state.get('fp_feedback', '')[:300]}")
    
    logger.info("\n[5] 정책 검증 에이전트 (Qwen sLLM)")
    logger.info(f"  result: {state.get('rule_validation_result')}")
    logger.info(f"  agent_judgement:")
    judgement = state.get('agent_judgement', '')
    if isinstance(judgement, dict):
        for k, v in judgement.items():
            logger.info(f"    {k}: {v}")
    else:
        logger.info(f"    {judgement[:500]}")
    
    logger.info("\n[6] 재시도 횟수")
    logger.info(f"  cti_analysis_retry: {state.get('cti_analysis_retry', 0)}")
    logger.info(f"  rule_generation_retry: {state.get('rule_generation_retry', 0)}")
    
    logger.info("\n[7] 최종 상태")
    logger.info(f"  status: {state.get('status')}")
    if state.get('error_message'):
        logger.info(f"  error_message: {state.get('error_message')}")
        logger.info(f"  error_node: {state.get('error_node')}")
    
    logger.info("=" * 80)


def _on_message(ch, method, properties, body):
    cti_data_id = None
    
    try:
        message = json.loads(body.decode("utf-8"))
        
        if "cti_data_id" not in message:
            logger.warning(
                f"[MQ Consumer] 잘못된 메시지 형식 (cti_data_id 없음) → 무시: "
                f"keys={list(message.keys())}"
            )
            ch.basic_ack(delivery_tag=method.delivery_tag)
            return
        
        payload = message
        cti_data_id = payload.get("cti_data_id", "unknown")
        
        logger.info(
            f"[MQ Consumer] 요청 수신: cti_id={cti_data_id}, "
            f"sid={payload.get('sid')!r}, "
            f"platform_id={payload.get('platform_id')}, "
            f"raw_content 길이={len(payload.get('raw_content', ''))}자"
        )

        logger.info(f"[DEBUG] raw_content: {payload.get('raw_content', '')[:200]}")
        
        final_state = _process_request(payload)
        
        logger.info(
            f"[MQ Consumer] 워크플로우 완료: cti_id={cti_data_id}, "
            f"status={final_state.get('status')}"
        )
        
        send_response_to_backend(final_state)
        
        ch.basic_ack(delivery_tag=method.delivery_tag)
    
    except json.JSONDecodeError as e:
        logger.error(f"[MQ Consumer] JSON 파싱 실패: {e}")
        ch.basic_ack(delivery_tag=method.delivery_tag)
    
    except ValueError as e:
        logger.error(f"[MQ Consumer] 입력 검증 실패: {e}")
        if cti_data_id:
            try:
                send_error_to_backend(cti_data_id, str(e))
            except Exception as send_err:
                logger.error(f"[MQ Consumer] 에러 응답 발행 실패: {send_err}")
        ch.basic_ack(delivery_tag=method.delivery_tag)
    
    except Exception as e:
        logger.exception(
            f"[MQ Consumer] 예외 발생: cti_id={cti_data_id}, "
            f"{type(e).__name__}: {e}"
        )
        if cti_data_id:
            try:
                send_error_to_backend(cti_data_id, str(e))
            except Exception as send_err:
                logger.error(f"[MQ Consumer] 에러 응답 발행 실패: {send_err}")
        ch.basic_ack(delivery_tag=method.delivery_tag)


def start_consumer() -> None:
    while True:
        connection = None
        try:
            logger.info(
                f"[MQ Consumer] RabbitMQ 연결 시도: {settings.rabbitmq_url}"
            )
            
            params = pika.URLParameters(settings.rabbitmq_url)
            params.heartbeat = 0
            params.blocked_connection_timeout = 600
            connection = pika.BlockingConnection(params)
            channel = connection.channel()
            
            channel.queue_declare(
                queue=settings.mq_request_queue,
                durable=True,
            )
            
            channel.basic_qos(prefetch_count=1)
            
            channel.basic_consume(
                queue=settings.mq_request_queue,
                on_message_callback=_on_message,
            )
            
            logger.info(
                f"[MQ Consumer] 수신 대기 시작: queue={settings.mq_request_queue}"
            )
            
            channel.start_consuming()
        
        except AMQPConnectionError as e:
            logger.error(
                f"[MQ Consumer] RabbitMQ 연결 실패: {e} → 5초 후 재시도"
            )
            time.sleep(5)
        
        except KeyboardInterrupt:
            logger.info("[MQ Consumer] 사용자 중단 → 종료")
            if connection and not connection.is_closed:
                connection.close()
            sys.exit(0)
        
        except Exception as e:
            logger.exception(
                f"[MQ Consumer] 예외 발생: {type(e).__name__}: {e} → 5초 후 재시도"
            )
            if connection and not connection.is_closed:
                connection.close()
            time.sleep(5)