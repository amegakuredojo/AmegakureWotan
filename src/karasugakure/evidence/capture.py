import logging
from pathlib import Path
from karasugakure.adapters.evidence import EvidenceAdapter
from karasugakure.adapters.web import WebAdapter

logger = logging.getLogger("karasugakure.evidence.capture")

class CaptureManager:
    def __init__(self):
        self.evidence_adapter = EvidenceAdapter()
        self.web_adapter = WebAdapter()

    def capture_html(self, url: str, filename: str) -> Path:
        """Downloads HTML content of URL and saves it as evidence."""
        logger.info(f"Capturing HTML page: {url}")
        html_content = self.web_adapter.fetch_page(url)
        if not html_content:
            raise ValueError(f"Unable to capture content from {url}")
            
        return self.evidence_adapter.store_raw_evidence(
            filename=filename,
            content=html_content.encode("utf-8"),
            folder="html"
        )
