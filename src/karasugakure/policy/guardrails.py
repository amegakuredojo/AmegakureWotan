import logging
from typing import Any, Dict

logger = logging.getLogger("karasugakure.policy.guardrails")

class GuardrailsPolicy:
    def __init__(self):
        # We can configure prohibited operations or keywords to comply with OPSEC
        self.prohibited_keywords = ["exploit", "hack", "payload", "attack", "malware"]

    def validate_task_intent(self, task: str) -> bool:
        """Ensures the task does not contain destructive/prohibited instructions."""
        task_lower = task.lower()
        for kw in self.prohibited_keywords:
            if kw in task_lower:
                logger.warning(f"Guardrail violation: task contains prohibited term '{kw}'")
                return False
        return True
