# tests/test_identity.py
from compliance_lab.identity import AgentIdentity


def test_generate_creates_identity_with_id():
    identity = AgentIdentity.generate("validator")
    assert identity.agent_id == "validator"


def test_generate_creates_unique_keys():
    id1 = AgentIdentity.generate("a")
    id2 = AgentIdentity.generate("b")
    assert id1.public_key_bytes() != id2.public_key_bytes()


def test_sign_and_verify():
    identity = AgentIdentity.generate("validator")
    message = b"control_check:target1:detail"
    signature = identity.sign(message)
    assert identity.verify(signature, message)


def test_verify_rejects_tampered_message():
    identity = AgentIdentity.generate("validator")
    signature = identity.sign(b"original")
    assert not identity.verify(signature, b"tampered")


def test_verify_rejects_wrong_key():
    id1 = AgentIdentity.generate("agent1")
    id2 = AgentIdentity.generate("agent2")
    signature = id1.sign(b"message")
    assert not id2.verify(signature, b"message")


def test_public_key_hex_is_hex_string():
    identity = AgentIdentity.generate("validator")
    hex_str = identity.public_key_hex()
    assert isinstance(hex_str, str)
    bytes.fromhex(hex_str)  # Raises if not valid hex
