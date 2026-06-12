from typing import List

class ScopePolicy:
    def __init__(self, allowed_domains: List[str] = None):
        self.allowed_domains = allowed_domains or []

    def is_in_scope(self, target: str) -> bool:
        """Determines if the target is within the approved target scope."""
        if not self.allowed_domains:
            return True # If empty, assume all targets are in scope for now
        return any(target.endswith(dom) for dom in self.allowed_domains)
