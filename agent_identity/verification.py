"""Identity verification — challenges and proof-of-identity."""

from __future__ import annotations

import hashlib
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ChallengeStatus(str, Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    EXPIRED = "expired"


@dataclass
class VerificationChallenge:
    """A cryptographic challenge sent to an agent to prove its identity."""

    challenge_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    did: str = ""
    nonce: str = field(default_factory=lambda: os.urandom(32).hex())
    expected_response: str = ""
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    status: ChallengeStatus = ChallengeStatus.PENDING

    def __post_init__(self) -> None:
        if self.expires_at == 0.0:
            self.expires_at = self.created_at + 300  # 5 min default
        if not self.expected_response and self.did:
            self.expected_response = hashlib.sha256(
                f"{self.nonce}:{self.did}".encode()
            ).hexdigest()

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "challenge_id": self.challenge_id,
            "did": self.did,
            "nonce": self.nonce,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "status": self.status.value,
        }


@dataclass
class VerificationResult:
    """Outcome of a verification attempt."""

    challenge_id: str
    did: str
    verified: bool
    reason: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "challenge_id": self.challenge_id,
            "did": self.did,
            "verified": self.verified,
            "reason": self.reason,
            "timestamp": self.timestamp,
        }


class Verifier:
    """Issues challenges and validates responses for agent identity verification.

    The verification flow:
    1. ``create_challenge(did)`` → ``VerificationChallenge``
    2. Agent computes response: ``sha256(nonce + ":" + did)``
    3. ``verify_response(challenge_id, response)`` → ``VerificationResult``

    Example::

        verifier = Verifier()
        challenge = verifier.create_challenge("did:agent:abc123")
        # agent computes: sha256(challenge.nonce + ":" + did)
        response = hashlib.sha256(f"{challenge.nonce}:did:agent:abc123".encode()).hexdigest()
        result = verifier.verify_response(challenge.challenge_id, response)
        assert result.verified
    """

    def __init__(self, challenge_ttl: float = 300) -> None:
        self._challenges: dict[str, VerificationChallenge] = {}
        self._results: list[VerificationResult] = []
        self._challenge_ttl = challenge_ttl

    def create_challenge(self, did: str) -> VerificationChallenge:
        """Create a new verification challenge for the given DID."""
        challenge = VerificationChallenge(
            did=did,
            expires_at=time.time() + self._challenge_ttl,
        )
        self._challenges[challenge.challenge_id] = challenge
        return challenge

    def verify_response(self, challenge_id: str, response: str) -> VerificationResult:
        """Check a response against an active challenge."""
        challenge = self._challenges.get(challenge_id)

        if challenge is None:
            return VerificationResult(
                challenge_id=challenge_id,
                did="",
                verified=False,
                reason="Challenge not found",
            )

        if challenge.status != ChallengeStatus.PENDING:
            return VerificationResult(
                challenge_id=challenge_id,
                did=challenge.did,
                verified=False,
                reason=f"Challenge already {challenge.status.value}",
            )

        if challenge.is_expired():
            challenge.status = ChallengeStatus.EXPIRED
            result = VerificationResult(
                challenge_id=challenge_id,
                did=challenge.did,
                verified=False,
                reason="Challenge expired",
            )
            self._results.append(result)
            return result

        if response == challenge.expected_response:
            challenge.status = ChallengeStatus.VERIFIED
            result = VerificationResult(
                challenge_id=challenge_id,
                did=challenge.did,
                verified=True,
                reason="Signature matched",
            )
        else:
            challenge.status = ChallengeStatus.FAILED
            result = VerificationResult(
                challenge_id=challenge_id,
                did=challenge.did,
                verified=False,
                reason="Response does not match expected value",
            )

        self._results.append(result)
        return result

    def get_challenge(self, challenge_id: str) -> VerificationChallenge | None:
        return self._challenges.get(challenge_id)

    def list_results(self, did: str | None = None) -> list[VerificationResult]:
        if did:
            return [r for r in self._results if r.did == did]
        return list(self._results)

    def cleanup_expired(self) -> int:
        """Remove expired challenges. Returns count removed."""
        expired = [
            cid
            for cid, ch in self._challenges.items()
            if ch.is_expired() and ch.status == ChallengeStatus.PENDING
        ]
        for cid in expired:
            self._challenges[cid].status = ChallengeStatus.EXPIRED
        return len(expired)
