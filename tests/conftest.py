from pathlib import Path

import pytest

from compliance_lab.identity import AgentIdentity


@pytest.fixture
def agent_identity():
    return AgentIdentity.generate("validator")


@pytest.fixture
def reporter_identity():
    return AgentIdentity.generate("reporter")


@pytest.fixture
def targets_dir():
    return Path(__file__).parent.parent / "data" / "targets"


@pytest.fixture
def controls_dir():
    return Path(__file__).parent.parent / "data" / "controls"


@pytest.fixture
def controls_yaml_path(controls_dir):
    return controls_dir / "nist-800-53-subset.yaml"


@pytest.fixture
def human_identity():
    return AgentIdentity.generate("human")
