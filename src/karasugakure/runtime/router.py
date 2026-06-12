import logging
from typing import Any, Dict, List
from karasugakure.policy.scope import ScopePolicy

logger = logging.getLogger("karasugakure.runtime.router")

class Router:
    def __init__(self):
        self.scope_policy = ScopePolicy()
        # Holds registered adapters or agents if needed
        self.routes: Dict[str, Any] = {}

    def route_task(self, agent_name: str, target: str, **kwargs) -> Dict[str, Any]:
        """Routes a given target scanning task to an agent and checks scope rules."""
        logger.info(f"Routing task '{agent_name}' for target '{target}'")
        
        # Guardrail check: Is target in scope?
        if not self.scope_policy.is_in_scope(target):
            logger.warning(f"Target '{target}' is OUT of scope!")
            return {
                "status": "failed",
                "reason": f"Target '{target}' is out of configured scope."
            }
            
        # Return routing parameters
        return {
            "status": "routed",
            "agent": agent_name,
            "target": target,
            "params": kwargs
        }
