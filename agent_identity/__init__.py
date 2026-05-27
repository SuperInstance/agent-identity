"""Agent Identity — cryptographic identity system for fleet agents.

Provides unique IDs, reputation tracking, identity verification,
registry lookup, and credential management for autonomous agents.
"""

from agent_identity.identity import AgentIdentity
from agent_identity.reputation import ReputationEngine, ReputationScore
from agent_identity.verification import VerificationChallenge, VerificationResult, Verifier
from agent_identity.registry import AgentRegistry
from agent_identity.credentials import Credential, CredentialStore, CredentialType

__version__ = "1.0.0"
__all__ = [
    "AgentIdentity",
    "ReputationEngine",
    "ReputationScore",
    "VerificationChallenge",
    "VerificationResult",
    "Verifier",
    "AgentRegistry",
    "Credential",
    "CredentialStore",
    "CredentialType",
]
