# Wayback downloader placeholder skill
import sys
import json
from amegakurewotan.adapters.archive import ArchiveAdapter

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 wayback_downloader.py <url>")
        sys.exit(1)
        
    url = sys.argv[1]
    adapter = ArchiveAdapter()
    snapshots = adapter.get_wayback_snapshots(url)
    print(json.dumps(snapshots, indent=2))
