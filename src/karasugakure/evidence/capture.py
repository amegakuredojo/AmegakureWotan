import logging
import tempfile
from pathlib import Path
from typing import Dict, Any
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

    def capture_page(self, url: str, base_filename: str) -> Dict[str, Any]:
        """
        Captures both HTML and screenshot of a URL.
        Integrates wkhtmltoimage or selenium in headless mode.
        If tools are missing, logs EVIDENCE_CAPTURE_DEGRADED and falls back to saving
        HTML only and returning the hash of the HTML as screenshot evidence minimum.
        """
        import subprocess
        import hashlib
        
        # 1. Capture HTML first
        html_path = self.capture_html(url, f"{base_filename}.html")
        html_content = html_path.read_text(encoding="utf-8")
        html_hash = hashlib.sha512(html_content.encode("utf-8")).hexdigest()
        
        screenshot_path = None
        screenshot_hash = None
        capture_method = None
        
        # 2. Try wkhtmltoimage
        try:
            temp_screenshot = Path(tempfile.gettempdir()) / f"{base_filename}.png"
            res = subprocess.run(
                ["wkhtmltoimage", "--quality", "80", url, str(temp_screenshot)],
                capture_output=True, text=True, timeout=20
            )
            if res.returncode == 0 and temp_screenshot.exists():
                # Store screenshot via EvidenceAdapter
                screenshot_data = temp_screenshot.read_bytes()
                screenshot_path = self.evidence_adapter.store_raw_evidence(
                    filename=f"{base_filename}.png",
                    content=screenshot_data,
                    folder="screenshots"
                )
                screenshot_hash = hashlib.sha512(screenshot_data).hexdigest()
                capture_method = "wkhtmltoimage"
                temp_screenshot.unlink()
        except Exception:
            pass
            
        # 3. Try Selenium if wkhtmltoimage failed
        if not screenshot_path:
            try:
                from selenium import webdriver
                from selenium.webdriver.chrome.options import Options
                
                chrome_options = Options()
                chrome_options.add_argument("--headless")
                chrome_options.add_argument("--no-sandbox")
                chrome_options.add_argument("--disable-dev-shm-usage")
                
                driver = webdriver.Chrome(options=chrome_options)
                driver.get(url)
                
                # Get screenshot
                temp_screenshot = Path(tempfile.gettempdir()) / f"{base_filename}.png"
                driver.save_screenshot(str(temp_screenshot))
                driver.quit()
                
                if temp_screenshot.exists():
                    screenshot_data = temp_screenshot.read_bytes()
                    screenshot_path = self.evidence_adapter.store_raw_evidence(
                        filename=f"{base_filename}.png",
                        content=screenshot_data,
                        folder="screenshots"
                    )
                    screenshot_hash = hashlib.sha512(screenshot_data).hexdigest()
                    capture_method = "selenium"
                    temp_screenshot.unlink()
            except Exception:
                pass
                
        # 4. Fallback if both failed
        if not screenshot_path:
            logger.warning(
                f"EVIDENCE_CAPTURE_DEGRADED: Screenshot capture failed for {url}. "
                f"No wkhtmltoimage or selenium tools available. "
                f"Using HTML hash {html_hash} as fallback evidence signature."
            )
            
            # Return degraded status with html hash as mock screenshot/degraded indicator
            screenshot_hash = html_hash
            capture_method = "degraded_html_hash"
            
        return {
            "html_path": str(html_path),
            "html_hash": html_hash,
            "screenshot_path": str(screenshot_path) if screenshot_path else None,
            "screenshot_hash": screenshot_hash,
            "capture_method": capture_method
        }
