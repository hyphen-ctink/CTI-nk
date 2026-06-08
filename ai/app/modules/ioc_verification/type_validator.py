# IoC type/형식 검증

import re
from typing import Any
from urllib.parse import urlparse

ALLOWED_IOC_TYPES = frozenset({"ip", "domain", "url", "hash"})

_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$"
)
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*\.[a-zA-Z]{2,}$"
)


def _normalize_ioc_type(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "ipv4": "ip",
        "ipv6": "ip",
        "ip_address": "ip",
        "domain_name": "domain",
        "hostname": "domain",
        "uri": "url",
        "md5": "hash",
        "sha1": "hash",
        "sha256": "hash",
        "sha_256": "hash",
        "file_hash": "hash",
    }
    mapped = aliases.get(normalized, normalized)
    return mapped if mapped in ALLOWED_IOC_TYPES else None


def _validate_ioc_value(ioc_type: str, ioc_value: str) -> bool:
    if not ioc_value or not ioc_value.strip():
        return False
    value = ioc_value.strip()
    if ioc_type == "ip":
        return bool(_IPV4_RE.match(value))
    if ioc_type == "domain":
        return bool(_DOMAIN_RE.match(value))
    if ioc_type == "url":
        parsed = urlparse(value if "://" in value else f"http://{value}")
        return bool(parsed.netloc or parsed.path)
    if ioc_type == "hash":
        return bool(_HASH_RE.match(value))
    return False


def validate_ioc_types(ioc_list: list[dict]) -> tuple[list[dict], list[str]]:
    if not ioc_list:
        return [], []

    valid: list[dict] = []
    errors: list[str] = []
    seen: set[tuple[str, str]] = set()

    for idx, item in enumerate(ioc_list):
        if not isinstance(item, dict):
            errors.append(f"[{idx}] IoC 항목이 dict가 아님")
            continue

        ioc_type = _normalize_ioc_type(item.get("ioc_type"))
        ioc_value = item.get("ioc_value")
        if not ioc_type:
            errors.append(f"[{idx}] 지원하지 않는 ioc_type: {item.get('ioc_type')}")
            continue
        if not isinstance(ioc_value, str) or not ioc_value.strip():
            errors.append(f"[{idx}] ioc_value가 비어 있음 ({ioc_type})")
            continue

        value = ioc_value.strip()
        if ioc_type == "hash":
            value = value.lower()

        if not _validate_ioc_value(ioc_type, value):
            errors.append(
                f"[{idx}] ioc_value 형식 오류 ({ioc_type}): {value[:80]}"
            )
            continue

        key = (ioc_type, value.lower())
        if key in seen:
            continue
        seen.add(key)

        valid.append({"ioc_type": ioc_type, "ioc_value": value})

    return valid, errors
