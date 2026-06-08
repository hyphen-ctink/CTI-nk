#LangGraph 조건부 분기 함수들.

import logging
from langgraph.graph import END
from app.graph.state import AgentState

logger = logging.getLogger(__name__)

# 최대 재시도 횟수
MAX_CTI_ANALYSIS_RETRY = 3
MAX_RULE_GENERATION_RETRY = 3
RULE_SKIP_ATTACK_TYPES = {"unknown"}


def route_after_ioc_verification(state: AgentState) -> str:
    result = state.get("ioc_verification_result", "")
    retry_count = state.get("cti_analysis_retry", 0)
    
    if state.get("status"):
        return END
    
    if result == "success":
        raw_attack_type = state.get("raw_attack_type", "")
        if raw_attack_type == "unknown":
            return "backend"
        return "rule_generation"
    
    if result == "re-extraction":
        if retry_count >= MAX_CTI_ANALYSIS_RETRY:
            return END
        return "cti_analysis"
    
    return END


def route_after_validation_agent(state: AgentState) -> str:
    result = state.get("rule_validation_result", "")
    retry_count = state.get("rule_generation_retry", 0)
    
    if state.get("status"):
        return END
    
    if result == "re-generation":
        if retry_count >= MAX_RULE_GENERATION_RETRY:
            return END
        return "rule_generation"
    return END


def finalize_state_before_end(state: AgentState) -> dict:
    if not state.get("status"):
        return {
            "status": "removed",
            "error_message": state.get("error_message", "재시도 한도 초과 또는 미처리 종료"),
        }
    return {}