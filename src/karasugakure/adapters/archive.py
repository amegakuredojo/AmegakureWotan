import logging
from typing import Dict, Any, List, Optional
from karasugakure.utils.net import make_tor_request

logger = logging.getLogger("karasugakure.adapters.archive")

class ArchiveAdapter:
    def __init__(self):
        self.name = "archive"

    def get_wayback_snapshots(self, target_url: str) -> List[Dict[str, Any]]:
        """Queries the Wayback Machine API for historical snapshots."""
        logger.info(f"Retrieving archive history for {target_url}")
        api_url = f"https://archive.org/wayback/available?url={target_url}"
        
        try:
            res = make_tor_request(api_url, timeout=8.0)
            if res.status_code == 200:
                data = res.json()
                snapshots = []
                archived = data.get("archived_snapshots", {})
                if "closest" in archived:
                    snapshots.append({
                        "timestamp": archived["closest"]["timestamp"],
                        "url": archived["closest"]["url"],
                        "status": archived["closest"]["status"]
                    })
                return snapshots
        except Exception as e:
            logger.error(f"Error querying Wayback machine for {target_url}: {e}")
            
        return []
