#LangGraph 워크플로우 정의 및 컴파일.

import logging
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

from app.graph.state import AgentState
from app.graph.nodes import (
    cti_analysis_node,
    ioc_verification_node,
    rule_generation_node,
    three_stage_validation_node,
    validation_agent_node,
    mark_ioc_only_node,
)
from app.graph.conditions import (
    route_after_ioc_verification,
    route_after_validation_agent,
)


logger = logging.getLogger(__name__)


def build_workflow():
    graph = StateGraph(AgentState)
    
    graph.add_node("cti_analysis", cti_analysis_node)
    graph.add_node("ioc_verification", ioc_verification_node)
    graph.add_node("mark_ioc_only", mark_ioc_only_node)
    graph.add_node("rule_generation", rule_generation_node)
    graph.add_node("three_stage_validation", three_stage_validation_node)
    graph.add_node("validation_agent", validation_agent_node)
    
    graph.add_edge(START, "cti_analysis")
    
    graph.add_edge("cti_analysis", "ioc_verification")
    
    graph.add_conditional_edges(
        "ioc_verification",
        route_after_ioc_verification,
        {
            "rule_generation": "rule_generation",
            "cti_analysis": "cti_analysis",
            "backend": "mark_ioc_only",
            END: END,
        },
    )

    graph.add_edge("mark_ioc_only", END)
    
    graph.add_edge("rule_generation", "three_stage_validation")
    
    graph.add_edge("three_stage_validation", "validation_agent")
    
    graph.add_conditional_edges(
        "validation_agent",
        route_after_validation_agent,
        {
            "rule_generation": "rule_generation",
            END: END,
        },
    )
    
    checkpointer = MemorySaver()
    compiled = graph.compile(checkpointer=checkpointer)
    
    logger.info("[workflow] LangGraph 워크플로우 컴파일 완료")
    return compiled


_workflow_instance = None


def get_workflow():
    global _workflow_instance
    if _workflow_instance is None:
        _workflow_instance = build_workflow()
    return _workflow_instance