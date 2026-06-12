import logging
from typing import Dict, Any, List, Optional
from karasugakure.utils.net import make_tor_request

logger = logging.getLogger("karasugakure.adapters.darkweb")

class DarkWebAdapter:
    def __init__(self):
        self.name = "darkweb"

    def query_onion(self, onion_url: str) -> Optional[str]:
        """Queries an onion site. Enforces routing through Tor proxy."""
        logger.info(f"Querying darkweb address: {onion_url}")
        try:
            # We strictly force Tor proxy
            res = make_tor_request(onion_url, force_tor=True, timeout=15.0, agent_name="hel")
            if res.status_code == 200:
                return res.text
            else:
                logger.warning(f"Onion page {onion_url} returned status {res.status_code}")
                return None
        except Exception as e:
            logger.error(f"Failed to reach onion site {onion_url}: {e}")
            return None
