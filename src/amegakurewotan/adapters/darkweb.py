import logging
from typing import Dict, Any, List, Optional
from amegakurewotan.utils.net import make_tor_request

logger = logging.getLogger("amegakurewotan.adapters.darkweb")

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
    def parse_leak_db(self, html: str, query: str) -> List[Dict[str, Any]]:
        """Parses leak database HTML content and extracts matches with email/hash/password."""
        import re
        results = []
        if not html:
            return results
        
        # Regex patterns
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
        
        # Process lines to find query matches
        for line in html.splitlines():
            if query.lower() in line.lower():
                emails = re.findall(email_pattern, line)
                hashes = re.findall(hash_pattern, line)
                
                # Try to extract passwords (e.g. from email:password or email:hash or user:pass)
                parts = [p.strip() for p in re.split(r'[:;|]', line) if p.strip()]
                password = None
                if len(parts) >= 2:
                    # Assume last part or second part might be password if it's not the email or hash
                    for part in reversed(parts):
                        if part not in emails and part not in hashes:
                            password = part
                            break
                
                results.append({
                    "line": line.strip(),
                    "emails": emails,
                    "hashes": hashes,
                    "password": password
                })
        return results

