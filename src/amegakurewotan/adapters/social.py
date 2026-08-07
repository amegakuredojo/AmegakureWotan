import logging
from typing import Dict, Any, List, Optional
from amegakurewotan.utils.net import make_tor_request

logger = logging.getLogger("amegakurewotan.adapters.social")

class SocialAdapter:
    def __init__(self):
        self.name = "social"

    def check_profile_exists(self, platform: str, username: str) -> Optional[str]:
        """Checks if a username exists on a social network using platform patterns."""
        urls = {
            "github": f"https://github.com/{username}",
            "twitter": f"https://twitter.com/{username}",
            "reddit": f"https://www.reddit.com/user/{username}"
        }
        
        url = urls.get(platform.lower())
        if not url:
            return None
            
        logger.info(f"Checking profile on {platform} for {username}")
        try:
            # Enforce Tor routing for Loki sensitive agent checks
            res = make_tor_request(url, method="GET", timeout=5.0, agent_name="loki", force_tor=True)
            if res.status_code == 200:
                return url
            elif res.status_code == 404:
                return None
            else:
                logger.warning(f"Platform {platform} returned status {res.status_code} for {username}")
                return None
        except Exception as e:
            logger.error(f"Error checking profile for {username} on {platform}: {e}")
            return None
