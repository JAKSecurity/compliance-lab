# tests/test_agents.py
from unittest.mock import AsyncMock, MagicMock

from compliance_lab.agents import ComplianceAgent, create_model_client
from compliance_lab.identity import AgentIdentity


def test_compliance_agent_has_identity(agent_identity):
    agent = ComplianceAgent(
        role="validator",
        identity=agent_identity,
        autogen_agent=MagicMock(),
    )
    assert agent.identity is agent_identity
    assert agent.identity.agent_id == "validator"


def test_compliance_agent_has_role():
    identity = AgentIdentity.generate("validator")
    agent = ComplianceAgent(
        role="validator",
        identity=identity,
        autogen_agent=MagicMock(),
    )
    assert agent.role == "validator"


def test_create_validator(agent_identity):
    mock_client = MagicMock()
    agent = ComplianceAgent.create_validator(agent_identity, mock_client)
    assert agent.role == "validator"
    assert agent.identity is agent_identity


def test_create_reporter(reporter_identity):
    mock_client = MagicMock()
    agent = ComplianceAgent.create_reporter(reporter_identity, mock_client)
    assert agent.role == "reporter"
    assert agent.identity is reporter_identity


def test_validator_and_reporter_have_different_system_prompts():
    mock_client = MagicMock()
    v = ComplianceAgent.create_validator(AgentIdentity.generate("v"), mock_client)
    r = ComplianceAgent.create_reporter(AgentIdentity.generate("r"), mock_client)
    v_prompt = v.autogen_agent._system_messages[0].content
    r_prompt = r.autogen_agent._system_messages[0].content
    assert v_prompt != r_prompt
    assert "validator" in v_prompt.lower() or "security" in v_prompt.lower()
    assert "reporter" in r_prompt.lower() or "summary" in r_prompt.lower()


async def test_compliance_agent_run_returns_text():
    identity = AgentIdentity.generate("validator")
    mock_autogen = AsyncMock()
    mock_result = MagicMock()
    mock_message = MagicMock()
    mock_message.content = '{"finding": "PASS", "evidence": "OK"}'
    mock_result.messages = [mock_message]
    mock_autogen.run.return_value = mock_result

    agent = ComplianceAgent(role="validator", identity=identity, autogen_agent=mock_autogen)
    result = await agent.run("check this")

    assert result == '{"finding": "PASS", "evidence": "OK"}'
    mock_autogen.run.assert_called_once_with(task="check this")


async def test_compliance_agent_run_calls_autogen():
    identity = AgentIdentity.generate("validator")
    mock_autogen = AsyncMock()
    mock_result = MagicMock()
    mock_message = MagicMock()
    mock_message.content = "response"
    mock_result.messages = [mock_message]
    mock_autogen.run.return_value = mock_result

    agent = ComplianceAgent(role="validator", identity=identity, autogen_agent=mock_autogen)
    await agent.run("my prompt")

    mock_autogen.run.assert_called_once_with(task="my prompt")


def test_create_model_client_returns_client():
    client = create_model_client(model="llama3.2:3b")
    assert client is not None
