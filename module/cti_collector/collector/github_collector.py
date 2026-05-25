import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

load_dotenv() 

API_KEY = os.getenv("GIT_API_KEY")

class GithubRESTCollector:
    def __init__(self, config: dict, platform_url: str):
        last_collected_at = config.get("last_collected_at")

        if last_collected_at is None:
            last_collected_at = datetime.now() - timedelta(days=7)

        elif isinstance(last_collected_at, str):
            last_collected_at = datetime.fromisoformat(last_collected_at)

        self.last_commit_sha = config["last_commit_sha"]
        self.platform_id = config["platform_id"]
        self.platform_url = platform_url
        self.headers = {
            "Authorization": f"token {API_KEY}"
        }

    # 커밋 내역 수집
    def get_commits(self):
        url = f"{self.platform_url}/commits"
        headers = self.headers.copy()
        headers["Accept"] = "application/vnd.github.v3+json"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    
    # DIFF 수집
    def get_commit_diff(self, sha):
        url = f"{self.platform_url}/commits/{sha}"
        headers = self.headers.copy()
        headers["Accept"] = "application/vnd.github.v3.diff"
        response = requests.get(url, headers=headers)

        if response.status_code == 422:
            return None
        
        response.raise_for_status()
        return response.text

    def parse_diff(self, diff_text):
        added = []
        removed = []

        for line in diff_text.split("\n"):
            if line.startswith("+") and not line.startswith("+++"):
                added.append(line[1:].strip())
            elif line.startswith("-") and not line.startswith("---"):
                removed.append(line[1:].strip())
        
        return added, removed
     
    # 크롤러
    def collect(self):
        commits = self.get_commits()
        results = []

        for commit in commits:
            sha = commit["sha"]

            if self.last_commit_sha and sha == self.last_commit_sha:
                break

            diff_text = self.get_commit_diff(sha)
            added, removed = self.parse_diff(diff_text)

            for line in added:
                if line == "":
                    continue

                result = {
                    "platform_id": self.platform_id,
                    "status": "success",
                    "last_commit_sha": sha,
                    "collected_at": datetime.now(),
                    "item": 
                        {
                            "source_url": commit["html_url"],
                            "raw_content": line,
                            "git_diff": "add"
                        }
                }
                results.append(result)
            
            for line in removed:
                if line == "":
                    continue
                
                result = {
                    "platform_id": self.platform_id,
                    "status": "success",
                    "last_commit_sha": sha,
                    "collected_at": datetime.now(),
                    "item": 
                        {
                            "source_url": commit["html_url"],
                            "raw_content": line,
                            "git_diff": "remove"
                        }
                }
                results.append(result)
            
        return results

class GithubQLCollector:
    def __init__(self, config: dict, platform_url: str, owner: str, repo: str):
        last_collected_at = config.get("last_collected_at")

        if last_collected_at is None:
            last_collected_at = datetime.now() - timedelta(days=7)

        elif isinstance(last_collected_at, str):
            last_collected_at = datetime.fromisoformat(last_collected_at)

        self.last_updated_at = last_collected_at
        self.owner = owner
        self.repo = repo
        self.platform_id = config["platform_id"]
        self.platform_url = platform_url
        self.headers = {
            "Authorization": f"Bearer {API_KEY}"
        }
    
    # 쿼리 생성
    def build_query(self, cursor=None):
        after = f', after: "{cursor}"' if cursor else ""

        return f"""
query {{
    repository(owner: "{self.owner}", name: "{self.repo}") {{
        issues(first: 10{after}, orderBy: {{field: UPDATED_AT, direction: DESC}}) {{
            nodes {{
                title
                body
                updatedAt
                url
                comments(first: 5) {{
                    nodes {{
                        body
                        updatedAt
                    }}
                }}
            }}
            pageInfo {{
                endCursor
                hasNextPage
            }}
        }}
    }}
}}
"""
    
    # 본문, 댓글 수집
    def fetch(self, query):
        response = requests.post(
            self.platform_url,
            json={"query": query},
            headers=self.headers
        )

        response.raise_for_status()
        return response.json()
    
    # 크롤러
    def collect(self):
        cursor = None
        results = []

        while True:
            query = self.build_query(cursor)
            data = self.fetch(query)
            repo_data = data.get("data", {}).get("repository")
            if not repo_data:
                return []
            
            issues = repo_data.get("issues")
            if not issues:
                return []

            for issue in issues["nodes"]:
                updated_at = datetime.fromisoformat(
                    issue["updatedAt"]).replace(tzinfo=None)

                if self.last_updated_at and updated_at <= self.last_updated_at:
                    return results
                
                comments = []
                for comment in issue["comments"]["nodes"]:
                    comment_at = datetime.fromisoformat(
                        comment["updatedAt"]).replace(tzinfo=None)
                    if self.last_updated_at and comment_at <= self.last_updated_at:
                        continue

                    comments.append({
                        "body": comment["body"],
                    })

                    if updated_at < comment_at:
                        updated_at = comment_at
                
                result = {
                    "platform_id": self.platform_id,
                    "status": "success",
                    "last_commit_sha": None,
                    "collected_at": updated_at,
                    "item": 
                        {
                            "source_url": issue["url"],
                            "raw_content": issue["body"] + "\n\n" + "comment\n".join(c["body"] for c in comments),
                            "title": issue["title"]
                        }
                }

                results.append(result)
            
            if not issues["pageInfo"]["endCursor"]:
                break

            cursor = issues["pageInfo"]["endCursor"]
        
        return results
