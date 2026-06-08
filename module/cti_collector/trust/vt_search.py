import requests
from dotenv import load_dotenv
import os

load_dotenv() 

API_KEY = os.getenv("VT_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3/search"

def search_vt(target: str) -> dict:
    headers = {
        "x-apikey": API_KEY
    }

    param = {
        "query": target
    }

    response = requests.get(
        BASE_URL,
        headers=headers,
        params=param
    )

    response.raise_for_status()
    return response.json()

def is_exist_vi(target: str) -> bool:
    result = search_vt(target)
    data = result.get("data", [])

    if not data:
        return False
    
    status = data[0].get("attributes", {}).get("last_analysis_stats", {})
    malicious = status.get("malicious", 0)
    suspicios = status.get("suspicious", 0)
    
    return malicious + suspicios > 0