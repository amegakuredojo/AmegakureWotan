class BaseAgent:
    def __init__(self, name: str, role: str):
        self.name = name
        self.role = role

    def execute(self, *args, **kwargs):
        raise NotImplementedError("Each agent must implement its execute method.")
