from datetime import datetime, timedelta
import feedparser
from bs4 import BeautifulSoup

class RedditCollector:
    def __init__(self, config: dict, platform_url: str):
        last_collected_at = config.get("last_collected_at")

        if last_collected_at is None:
            last_collected_at = datetime.now() - timedelta(days=7)

        elif isinstance(last_collected_at, str):
            last_collected_at = datetime.fromisoformat(last_collected_at)

        self.platform_id = config["platform_id"]
        self.last_collected_at = last_collected_at
        self.platform_url = platform_url

    def get_recent_entries(self, limit=10):
        feed = feedparser.parse(self.platform_url)
        results = []
 
        for entry in feed.entries:
            if hasattr(entry, "published_parsed"):
                published = datetime(*entry.published_parsed[:6])

                if published >= self.last_collected_at:
                    content_html = ""
                    if "content" in entry:
                        content_html = entry.content[0].value 

                    results.append({
                        "title": entry.title,
                        "link": entry.link,
                        "published": entry.published,
                        "summary": entry.summary,
                        "content": content_html
                    })

                    if len(results) == limit:
                        break
        
        return results

     # HTML 본문 필터링 
    def html_to_text(self, html):
        soup = BeautifulSoup(html, "html.parser")
        return soup.get_text(separator=" ", strip=True)
    
    def collect(self):
        entries = self.get_recent_entries()
        results = []
        
        for entry in entries:
            content_text = self.html_to_text(entry["content"])

            result = {
                "platform_id": self.platform_id,
                "status": "success",
                "last_commit_sha": None,
                "collected_at": entry["published"],
                "item": 
                    {
                        "source_url": entry["link"],
                        "raw_content": entry["title"] + "\n\n" + content_text,
                        "git_diff": None
                    }
            }
            results.append(result)

        return results