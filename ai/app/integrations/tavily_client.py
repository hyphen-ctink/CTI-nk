#Tavily 검색 API 클라이언트.

from functools import lru_cache
from typing import Optional

from app.config import settings


class TavilyNotConfiguredError(Exception):
    pass


@lru_cache
def _get_tavily_client():
    if not settings.tavily_api_key:
        raise TavilyNotConfiguredError(
            "TAVILY_API_KEY가 .env에 설정되지 않았습니다. "
            "Tavily API 키를 발급받아 .env에 추가하세요. "
            "https://tavily.com 에서 무료 가입 가능합니다."
        )
    
    from tavily import TavilyClient
    return TavilyClient(api_key=settings.tavily_api_key)


def tavily_search(query: str, max_results: int = 5) -> dict:
    client = _get_tavily_client()
    return client.search(query=query, max_results=max_results)


def is_tavily_available() -> bool:
    return bool(settings.tavily_api_key)