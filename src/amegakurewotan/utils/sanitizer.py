import re
import logging
from typing import Any, Dict, List, Union

logger = logging.getLogger("amegakurewotan.utils.sanitizer")

PROMPT_INJECTION_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?(previous\s+)?(instructions|commands|directions)",
    r"(?i)disregard\s+(all\s+)?(previous\s+)?(instructions|commands|directions)",
    r"(?i)system\s*prompt",
    r"(?i)you\s+are\s+(now\s+)?(a\s+)?",
    r"(?i)new\s+rule[s]?:",
    r"(?i)forget\s+(all\s+)?(previous\s+)?",
    r"(?i)bypass\s+(all\s+)?",
    r"```(?!json|xml|yaml|csv|txt)[a-zA-Z]+",  # Prevent arbitrary code block execution
]

MAX_STRING_LENGTH = 1000

class OSINTSanitizer:
    @classmethod
    def sanitize_string(cls, text: str) -> str:
        """
        Sanitize a single string by stripping prompt injection payloads
        and enforcing length limits to prevent DoS.
        """
        if not isinstance(text, str):
            return text
            
        original_text = text
        # Truncate to prevent token exhaustion DoS
        if len(text) > MAX_STRING_LENGTH:
            text = text[:MAX_STRING_LENGTH] + "... [TRUNCATED]"
            
        # Strip injection patterns
        for pattern in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, text):
                logger.warning(f"Detected potential prompt injection in OSINT data. Sanitizing.")
                text = re.sub(pattern, "[REDACTED_INJECTION_ATTEMPT]", text)
                
        # Remove control characters except standard whitespace
        text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', text)
        
        return text.strip()

    @classmethod
    def sanitize_payload(cls, payload: Union[Dict, List, str, Any]) -> Union[Dict, List, str, Any]:
        """
        Recursively sanitize all strings within a complex payload (dict, list).
        """
        if isinstance(payload, str):
            return cls.sanitize_string(payload)
        elif isinstance(payload, dict):
            return {k: cls.sanitize_payload(v) for k, v in payload.items()}
        elif isinstance(payload, list):
            return [cls.sanitize_payload(item) for item in payload]
        else:
            # Numbers, booleans, None
            return payload
