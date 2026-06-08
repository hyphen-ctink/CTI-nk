# IoC 검증 시 활용하는 외부 도구 조회 모듈.

from typing import Optional

from app.integrations.tavily_client import (
    is_tavily_available,
    tavily_search,
    TavilyNotConfiguredError,
)


def _ioc_in_search_results(ioc_value: str, raw_results: list) -> bool:
    needle = ioc_value.lower().strip()
    if not needle:
        return False

    for result in raw_results:
        url = (result.get("url") or "").lower()
        title = (result.get("title") or "").lower()
        content = (result.get("content") or "").lower()
        blob = f"{url} {title} {content}"
        if needle in blob:
            return True
    return False


def query_virustotal_via_tavily(ioc_value: str, ioc_type: str) -> dict:
    if not is_tavily_available():
        return {
            "found": False,
            "exists_on_vt": False,
            "malicious_indicators": [],
            "raw_results": [],
            "error": "Tavily API 키 미설정 - 외부 검증 스킵",
        }

    query = f"VirusTotal {ioc_type} {ioc_value}"

    try:
        results = tavily_search(query, max_results=5)
        raw_results = results.get("results", [])

        malicious_keywords = [
            "malicious", "malware", "phishing", "ransomware",
            "trojan", "c2", "botnet", "exploit", "vulnerability",
            "악성", "위협", "공격",
        ]

        malicious_indicators = []
        vt_linked = False
        for r in raw_results:
            url = (r.get("url") or "").lower()
            content = (r.get("content", "") + " " + r.get("title", "")).lower()
            if "virustotal.com" in url:
                vt_linked = True
            for keyword in malicious_keywords:
                if keyword in content:
                    malicious_indicators.append({
                        "keyword": keyword,
                        "source": r.get("url", ""),
                        "snippet": r.get("content", "")[:200],
                    })
                    break

        ioc_mentioned = _ioc_in_search_results(ioc_value, raw_results)
        exists_on_vt = bool(raw_results) and (vt_linked or ioc_mentioned)

        return {
            "found": len(raw_results) > 0,
            "exists_on_vt": exists_on_vt,
            "malicious_indicators": malicious_indicators,
            "raw_results": raw_results,
            "error": None,
        }

    except TavilyNotConfiguredError as e:
        return {
            "found": False,
            "exists_on_vt": False,
            "malicious_indicators": [],
            "raw_results": [],
            "error": str(e),
        }
    except Exception as e:
        return {
            "found": False,
            "exists_on_vt": False,
            "malicious_indicators": [],
            "raw_results": [],
            "error": f"Tavily 검색 실패: {type(e).__name__}: {e}",
        }


def exists_on_virustotal_via_tavily(ioc_value: str, ioc_type: str) -> bool:
    """VirusTotal에 해당 IoC 조회 결과가 있는지 (Tavily 검색 기반)."""
    result = query_virustotal_via_tavily(ioc_value, ioc_type)
    if result.get("error"):
        return False
    return bool(result.get("exists_on_vt"))


def is_ioc_in_raw_content(ioc_value: str, raw_content: str) -> bool:
    if not ioc_value or not raw_content:
        return False

    return ioc_value.lower() in raw_content.lower()
