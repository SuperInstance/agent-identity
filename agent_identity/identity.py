"""Core agent identity — unique ID generation, metadata, and DID documents."""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


@dataclass(frozen=True)
class AgentIdentity:
    """A cryptographic identity for a fleet agent.

    Each identity has a globally unique DID (Decentralized Identifier),
    a human-readable name, arbitrary metadata, and a creation timestamp.
    Identities are immutable after creation — use the registry for updates.

    Example::

        agent = AgentIdentity(name="navigator-01")
        print(agent.did)        # did:agent:a3f7...
        print(agent.agent_id)   # UUID string
    """

    name: str
    agent_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    public_key: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    did: str = field(init=False)
    _did_seed: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("Agent name must not be empty")
        seed = self._did_seed or f"{self.agent_id}:{self.name}:{self.created_at}"
        hash_hex = _sha256(seed)
        # Use object.__setattr__ because the dataclass is frozen
        object.__setattr__(self, "did", f"did:agent:{hash_hex}")

    # -- DID document --------------------------------------------------

    def did_document(self) -> dict[str, Any]:
        """Return a W3C-compliant DID document for this agent."""
        key_ref = f"{self.did}#key-1"
        doc: dict[str, Any] = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            "id": self.did,
            "verificationMethod": [
                {
                    "id": key_ref,
                    "type": "Ed25519VerificationKey2020",
                    "controller": self.did,
                    "publicKeyMultibase": self.public_key or _sha256(self.agent_id),
                }
            ],
            "authentication": [key_ref],
            "assertionMethod": [key_ref],
        }
        return doc

    # -- Fingerprint ---------------------------------------------------

    def fingerprint(self) -> str:
        """Short 16-char hex fingerprint for quick visual comparison."""
        return _sha256(self.did)[:16]

    # -- Serialization -------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "did": self.did,
            "public_key": self.public_key,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentIdentity:
        """Reconstruct from a dict produced by ``to_dict``."""
        return cls(
            name=data["name"],
            agent_id=data["agent_id"],
            public_key=data.get("public_key", ""),
            metadata=data.get("metadata", {}),
            created_at=data.get("created_at", time.time()),
            _did_seed=f"{data['agent_id']}:{data['name']}:{data.get('created_at', '')}",
        )

    def __repr__(self) -> str:
        return f"AgentIdentity(name={self.name!r}, did={self.did[:24]}…)"
