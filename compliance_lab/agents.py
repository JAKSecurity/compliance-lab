# compliance_lab/agents.py
"""ComplianceAgent — combines AutoGen AssistantAgent with cryptographic identity."""

from autogen_agentchat.agents import AssistantAgent
from autogen_ext.models.openai import OpenAIChatCompletionClient

from compliance_lab.agent import REPORTER_SYSTEM_PROMPT, SYSTEM_PROMPT
from compliance_lab.identity import AgentIdentity


def create_model_client(
    model: str = "llama3.2:3b",
    base_url: str = "http://localhost:11434/v1",
) -> OpenAIChatCompletionClient:
    """Create an OpenAI-compatible model client pointing at Ollama."""
    return OpenAIChatCompletionClient(
        model=model,
        api_key="not-needed",
        base_url=base_url,
        model_info={
            "vision": False,
            "function_calling": False,
            "json_output": False,
            "structured_output": False,
            "family": "unknown",
        },
    )


class ComplianceAgent:
    """Wrapper combining an AutoGen AssistantAgent with a cryptographic AgentIdentity."""

    def __init__(
        self,
        role: str,
        identity: AgentIdentity,
        autogen_agent: AssistantAgent,
    ):
        self.role = role
        self.identity = identity
        self.autogen_agent = autogen_agent

    @classmethod
    def create_validator(
        cls, identity: AgentIdentity, model_client
    ) -> "ComplianceAgent":
        """Create a validator agent."""
        agent = AssistantAgent(
            name="validator",
            model_client=model_client,
            system_message=SYSTEM_PROMPT,
        )
        return cls(role="validator", identity=identity, autogen_agent=agent)

    @classmethod
    def create_reporter(
        cls, identity: AgentIdentity, model_client
    ) -> "ComplianceAgent":
        """Create a reporter agent."""
        agent = AssistantAgent(
            name="reporter",
            model_client=model_client,
            system_message=REPORTER_SYSTEM_PROMPT,
        )
        return cls(role="reporter", identity=identity, autogen_agent=agent)

    async def run(self, prompt: str) -> str:
        """Run the agent on a prompt and return the response text."""
        result = await self.autogen_agent.run(task=prompt)
        return result.messages[-1].content
