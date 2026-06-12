import logging
from typing import Any, Dict
from karasugakure.runtime.session import Session
from karasugakure.runtime.router import Router

logger = logging.getLogger("karasugakure.runtime.harness")

class Harness:
    def __init__(self, session_id: str = "default"):
        self.session = Session(session_id)
        self.session.load()
        self.router = Router()

    def run_agent_task(self, agent_class: Any, target: str, **kwargs) -> Dict[str, Any]:
        """Runs an agent inside the environment harness with scoping and logging."""
        agent = agent_class()
        
        # Verify scoping
        route_decision = self.router.route_task(agent.name, target, **kwargs)
        if route_decision["status"] != "routed":
            return route_decision

        logger.info(f"Harness launching agent {agent.name} on target {target}")
        try:
            results = agent.execute(target, **kwargs)
            self.session.add_target(target, agent.name)
            self.session.log_action(agent.name, f"execute on {target}", f"Discovered assets: {len(results)}")
            return {
                "status": "success",
                "agent": agent.name,
                "results": results
            }
        except Exception as e:
            logger.error(f"Agent {agent.name} failed during execution: {e}")
            return {
                "status": "error",
                "agent": agent.name,
                "error": str(e)
            }
