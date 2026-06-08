#Ollama 로컬 LLM 클라이언트.

from functools import lru_cache
from langchain_ollama import ChatOllama
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)
import httpx

from app.config import settings


@lru_cache
def get_rule_generator_client(temperature: float = 0.2) -> ChatOllama:
    return ChatOllama(
        model=settings.ollama_rule_model,
        base_url=settings.ollama_base_url,
        temperature=temperature,
    )


@lru_cache
def get_ioc_validator_client(temperature: float = 0.1) -> ChatOllama:
    return ChatOllama(
        model=settings.ollama_ioc_model,
        base_url=settings.ollama_base_url,
        temperature=temperature,
    )


@lru_cache
def get_rule_validator_client(temperature: float = 0.0) -> ChatOllama:
    return ChatOllama(
        model=settings.ollama_rule_validation_model,
        base_url=settings.ollama_base_url,
        temperature=temperature,
    )


ollama_retry = retry(
    stop=stop_after_attempt(settings.max_infrastructure_retry),
    wait=wait_exponential(multiplier=1, min=1, max=16),
    retry=retry_if_exception_type(
        (
            httpx.ConnectError,   
            httpx.TimeoutException, 
            httpx.HTTPStatusError,  
        )
    ),
    reraise=True,
)


@ollama_retry
def invoke_rule_generator(prompt: str) -> str:
    client = get_rule_generator_client()
    response = client.invoke(prompt)
    return response.content


@ollama_retry
def invoke_ioc_validator(prompt: str) -> str:
    client = get_ioc_validator_client()
    response = client.invoke(prompt)
    return response.content


@ollama_retry
def invoke_rule_validator(prompt: str) -> str:
    client = get_rule_validator_client()
    response = client.invoke(prompt)
    return response.content