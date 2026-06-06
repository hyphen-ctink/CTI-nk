#프로젝트 전체 설정 관리 모듈.

from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    anthropic_api_key: str = Field(..., description="Anthropic API 인증 키")
    anthropic_model: str = Field(
        default="claude-sonnet-4-6",
        description="CTI 분석 및 IoC 추출에 사용할 Claude 모델 ID"
    )

    ollama_base_url: str = Field(
        default="http://host.docker.internal:11434",
        description="Ollama 서버 URL (WSL → Windows 호스트 통신)"
    )
    ollama_rule_model: str = Field(
        default="llama3.1:latest",
        description="탐지 정책 생성용 sLLM 모델"
    )
    ollama_ioc_model: str = Field(
        default="llama3.1:latest",
        description="IoC 검증용 sLLM 모델"
    )
    ollama_rule_validation_model: str = Field(
        default="Qwen2.5-7B-Instruct.Q4_K_M.gguf:latest",
        description="탐지 정책 검증용 sLLM 모델"
    )

    tavily_api_key: str = Field(
        default="",
        description="Tavily 검색 API 키"
    )
   
    rabbitmq_host: str = Field(default="localhost")
    rabbitmq_port: int = Field(default=5672)
    rabbitmq_user: str = Field(default="guest")
    rabbitmq_password: str = Field(default="guest")

    rabbitmq_url: str = Field(
        default="amqp://guest:guest@localhost:5672/",
        description="RabbitMQ AMQP URL",
    )
    mq_request_queue: str = Field(
        default="ctink.test.request.queue",
        description="요청 큐 (로컬 테스트)",
    )
    mq_response_queue: str = Field(
        default="ctink.test.result.queue",
        description="응답 큐 (로컬 테스트)",
    )

    app_env: str = Field(default="development", description="실행 환경: development/production")
    log_level: str = Field(default="INFO", description="로그 레벨")
    
    max_retry_count: int = Field(
        default=3,
        description="LLM 호출 최대 재시도 횟수"
    )
    max_infrastructure_retry: int = Field(
        default=5,
        description="인프라 레벨 자동 재시도 횟수"
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,  
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
