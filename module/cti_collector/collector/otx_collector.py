from datetime import datetime, timedelta
from typing import List, Dict
import requests
from dotenv import load_dotenv
import os

load_dotenv() 

API_KEY = os.getenv("OTX_API_KEY")

headers = {
    "X-OTX-API-KEY": API_KEY,
    "User-Agent": "Mozilla/5.0"
}

class OTXCollector:
    def __init__(self, config: dict, platform_url: str):
        last_collected_at = config.get("last_collected_at")

        if last_collected_at is None:
            last_collected_at = datetime.now() - timedelta(days=7)

        elif isinstance(last_collected_at, str):
            last_collected_at = datetime.fromisoformat(last_collected_at)
        
        self.last_collected_at = last_collected_at
        self.platform_id = config["platform_id"]
        self.platform_url = platform_url
        self.page = 1
        self.limit = 10
    
    # OTX Pulse 목록 가져오기
    def fetch_pulses(self) -> List[Dict]:
        params = {
            "limit": self.limit,
            "page": self.page
        }

        response = requests.get(self.platform_url, headers=headers, params=params)
        
        if response.status_code != 200:
            print(response.status_code)
            print(response.text)
            return []

        data = response.json()
        return data.get("results", [])
    
    # 크롤러
    def collect(self) -> List[Dict]:
        filtered_datas = []
        seen_datas = set()

        while True:
            pulses = self.fetch_pulses()

            if not pulses:
                break

            for pulse in pulses:
                created = pulse.get("created")
                created_time = datetime.fromisoformat(created)
                
                for ioc in pulse.get("indicators", []):
               
                    if created_time > self.last_collected_at:
                        key = ioc.get("id")
                        if key not in seen_datas:
                            filtered_data = {
                                "platform_id": self.platform_id,
                                "status": "success",
                                "last_commit_sha": None,
                                "collected_at": created,
                                "item": 
                                    {
                                        "source_url": "",
                                        "raw_content": ioc.get("indicator"),
                                        "git_diff": None
                                    }
                            }
                            filtered_datas.append(filtered_data)
                            seen_datas.add(key)
                    else:
                        break
                
                if created_time <= self.last_collected_at:
                    continue
            if len(pulses) >= self.limit:
                break

            self.page += 1
        
        return filtered_datas