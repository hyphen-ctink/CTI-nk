#LangGraph 워크플로우의 상태(State) 정의.

from typing import Optional, TypedDict
from typing_extensions import NotRequired


class IoC(TypedDict):
    ioc_type: str 
    ioc_value: str


class DetectionRule(TypedDict):
    ioc_type: str       
    rule_type: str 
    rule_content: str   
    os_type: NotRequired[str] 


class ValidationFeedback(TypedDict):
    grammar_result: NotRequired[str]
    grammar_feedback: NotRequired[str]
    fn_result: NotRequired[str]
    fn_feedback: NotRequired[str]
    fp_result: NotRequired[str]
    fp_feedback: NotRequired[str]
    agent_result: NotRequired[str]
    agent_feedback: NotRequired[str]


class AgentState(TypedDict):
    cti_data_id: int      
    sid: int 
    platform_id: int        
    raw_content: str        

    raw_attack_type: NotRequired[str]
    is_ioc_only: NotRequired[bool]
    attack_type: NotRequired[str]
    attack_detail: NotRequired[list[dict]]
    summary: NotRequired[str]             
    ioc_list: NotRequired[list[IoC]]       
   
    virustotal_result: NotRequired[str]    
    ioc_verification_result: NotRequired[str]
    ioc_feedback: NotRequired[str]         
    
    detection_rule: NotRequired[list[DetectionRule]]
    
    grammar_result: NotRequired[str]       
    grammar_feedback: NotRequired[str]
    fn_result: NotRequired[str]           
    fn_feedback: NotRequired[str]
    fp_result: NotRequired[str]           
    fp_feedback: NotRequired[str]
    
    rule_validation_result: NotRequired[str]
    agent_judgement: NotRequired[str]      
   
    cti_analysis_retry: NotRequired[int]   
    rule_generation_retry: NotRequired[int] 
    regen_count: NotRequired[int]         

    status: NotRequired[str]               
    error_message: NotRequired[str]        
    error_node: NotRequired[str]           