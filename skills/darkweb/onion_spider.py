# Onion spider placeholder skill
import sys
from karasugakure.adapters.darkweb import DarkWebAdapter

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 onion_spider.py <onion_url>")
        sys.exit(1)
        
    onion = sys.argv[1]
    adapter = DarkWebAdapter()
    content = adapter.query_onion(onion)
    if content:
        print(f"Content length: {len(content)}")
    else:
        print("Failed to retrieve content.")
