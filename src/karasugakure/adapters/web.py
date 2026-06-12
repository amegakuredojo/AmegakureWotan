import logging
from typing import Any, Dict
from karasugakure.utils.net import make_tor_request

logger = logging.getLogger("karasugakure.adapters.web")

class WebAdapter:
    def __init__(self):
        self.name = "web"

    def fetch_page(self, url: str, use_tor: bool = False) -> str:
        """Fetches html/text content from a url with UA rotation and optional Tor."""
        logger.info(f"Fetching page: {url} (Tor: {use_tor})")
        try:
            res = make_tor_request(url, force_tor=use_tor, agent_name="heimdall")
            if res.status_code == 200:
                return res.text
            else:
                logger.warning(f"Failed to fetch {url}: HTTP {res.status_code}")
                return ""
        except Exception as e:
            logger.error(f"Error fetching page {url}: {e}")
            return ""
