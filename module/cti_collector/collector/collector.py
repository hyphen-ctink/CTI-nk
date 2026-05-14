from collector.medium_collector import MediumCollector
from collector.otx_collector import OTXCollector
from collector.github_collector import GithubRESTCollector, GithubQLCollector
from collector.reddit_collector import RedditCollector

URL = {
    1: "https://medium.com/feed/@anyrun",
    2: "https://otx.alienvault.com/api/v1/pulses/subscribed",
    3: f"https://api.github.com/repos/eset/malware-ioc",
    4: f"https://api.github.com/repos/Cisco-Talos/IOCs",
    5: f"https://api.github.com/repos/stamparm/ipsum",
    6: f"https://api.github.com/repos/aquasecurity/vuln-list",
    7: f"https://api.github.com/graphql",
    9: f"https://www.reddit.com/r/threatintel/.rss",
    10: f"https://www.reddit.com/r/blueteamsec/.rss",
    11: f"https://www.reddit.com/r/netsec/.rss",
    12: f"https://www.reddit.com/r/CyberSecurity/.rss"
}

def collector_start(json: dict): 
    platform_id = json.get("platform_id") 
    
    try: 
        results = []

        platform_id = json.get("platform_id") 
        
        if platform_id == 1:
            collector = MediumCollector(json, URL[1])  
            results = collector.collect()
        
        elif platform_id == 2:
            collector = OTXCollector(json, URL[2])
            results = collector.collect()

        elif platform_id == 3:
            collector = GithubRESTCollector(json, URL[3])
            results = collector.collect()
        
        elif platform_id == 4:
            collector = GithubRESTCollector(json, URL[4])
            results = collector.collect()

        elif platform_id == 5:
            collector = GithubRESTCollector(json, URL[5])
            results = collector.collect()
        
        elif platform_id == 6:
            collector = GithubRESTCollector(json, URL[6])
            results = collector.collect()

        elif platform_id == 7:
            collector = GithubQLCollector(json, URL[7], "Velocidex", "velociraptor")
            results = collector.collect()
        
        elif platform_id == 8:
            collector = GithubQLCollector(json, URL[7], "Security-Onion-Solutions", "securityonion")
            results = collector.collect()
        
        elif platform_id == 9:
            collector = RedditCollector(json, URL[9])
            results = collector.collect()
        
        elif platform_id == 10:
            collector = RedditCollector(json, URL[10])
            results = collector.collect()
        
        elif platform_id == 11:
            collector = RedditCollector(json, URL[11])
            results = collector.collect()

        elif platform_id == 12:
            collector = RedditCollector(json, URL[12])
            results = collector.collect()
        
        return results
    
    except Exception as e:
        print("collector error:", e)