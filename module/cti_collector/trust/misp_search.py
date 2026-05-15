import requests
import urllib3
import json
from dotenv import load_dotenv
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv() 

API_KEY = os.getenv("MISP_API_KEY")
MISP_URL = "https://localhost/attributes/restSearch"

def search_misp(target: str, limit: int = 3) -> dict:
    headers = {
        "Authorization": API_KEY,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    payload = {
        "value": target,
        "limit": limit
    }

    response = requests.post(MISP_URL, headers=headers, data=json.dumps(payload), verify=False)

    response.raise_for_status()
    
    return response.json()

def is_exist_misp(target: str) -> bool:
    result = search_misp(target)
    attributes = result.get("response", {}).get("Attribute", [])
    return len(attributes) > 0