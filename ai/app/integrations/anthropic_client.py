#Anthropic Claude API 클라이언트.

from functools import lru_cache
from langchain_anthropic import ChatAnthropic
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)
import anthropic

from app.config import settings


@lru_cache
def get_claude_client(max_tokens: int = 4096, temperature: float = 0.1) -> ChatAnthropic:
    return ChatAnthropic(
        model=settings.anthropic_model,
        api_key=settings.anthropic_api_key,
        max_tokens=max_tokens,
        temperature=temperature,
    )

claude_retry = retry(
    stop=stop_after_attempt(settings.max_infrastructure_retry),
    wait=wait_exponential(multiplier=1, min=1, max=16),
    retry=retry_if_exception_type(
        (
            anthropic.APIConnectionError,  
            anthropic.APITimeoutError,      
            anthropic.RateLimitError,       
            anthropic.InternalServerError,  
        )
    ),
    reraise=True,
)


@claude_retry
def invoke_claude(prompt: str, max_tokens: int = 4096) -> str:
    client = get_claude_client(max_tokens=max_tokens)
    response = client.invoke(prompt)
    return response.content