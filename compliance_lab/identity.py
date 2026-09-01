# compliance_lab/identity.py
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class AgentIdentity:
    """Cryptographic identity for an agent. Ed25519 keypair."""

    def __init__(self, agent_id: str, private_key: Ed25519PrivateKey):
        self.agent_id = agent_id
        self._private_key = private_key
        self._public_key = private_key.public_key()

    @classmethod
    def generate(cls, agent_id: str) -> "AgentIdentity":
        return cls(agent_id, Ed25519PrivateKey.generate())

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)

    def verify(self, signature: bytes, message: bytes) -> bool:
        try:
            self._public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    def public_key_bytes(self) -> bytes:
        return self._public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    def public_key_hex(self) -> str:
        return self.public_key_bytes().hex()
