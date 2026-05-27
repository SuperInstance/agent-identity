"""Reputation system — scoring, decay, and endorsements."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ReputationLevel(str, Enum):
    NEW = "new"
    BRONZE = "bronze"
    SILVER = "silver"
    GOLD = "gold"
    PLATINUM = "platinum"


@dataclass
class Endorsement:
    """A peer endorsement from one agent to another."""

    from_did: str
    to_did: str
    weight: float = 1.0
    reason: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class ReputationScore:
    """Computed reputation for an agent."""

    score: float = 0.0
    level: ReputationLevel = ReputationLevel.NEW
    endorsements: list[Endorsement] = field(default_factory=list)
    last_updated: float = field(default_factory=time.time)
    decay_rate: float = 0.02  # per day

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "level": self.level.value,
            "endorsement_count": len(self.endorsements),
            "last_updated": self.last_updated,
        }


def _level_for(score: float) -> ReputationLevel:
    if score >= 90:
        return ReputationLevel.PLATINUM
    if score >= 70:
        return ReputationLevel.GOLD
    if score >= 50:
        return ReputationLevel.SILVER
    if score >= 20:
        return ReputationLevel.BRONZE
    return ReputationLevel.NEW


class ReputationEngine:
    """Tracks and computes agent reputation over time.

    Features:
    - Add / remove endorsements
    - Time-based decay (older contributions lose weight)
    - Score is always 0–100
    - Levels: NEW → BRONZE → SILVER → GOLD → PLATINUM

    Example::

        engine = ReputationEngine()
        engine.add_endorsement("did:agent:alice", "did:agent:bob")
        print(engine.get_score("did:agent:bob").score)
    """

    def __init__(self, decay_rate: float = 0.02) -> None:
        self._scores: dict[str, ReputationScore] = {}
        self.decay_rate = decay_rate

    # -- Endorsements --------------------------------------------------

    def add_endorsement(
        self,
        from_did: str,
        to_did: str,
        weight: float = 1.0,
        reason: str = "",
    ) -> Endorsement:
        """Record a peer endorsement and recalculate score."""
        if to_did not in self._scores:
            self._scores[to_did] = ReputationScore(decay_rate=self.decay_rate)
        rep = self._scores[to_did]

        endorsement = Endorsement(
            from_did=from_did,
            to_did=to_did,
            weight=weight,
            reason=reason,
        )
        rep.endorsements.append(endorsement)
        self._recalculate(to_did)
        return endorsement

    def remove_endorsements_from(self, from_did: str, to_did: str) -> int:
        """Remove all endorsements from *from_did* to *to_did*. Returns count removed."""
        if to_did not in self._scores:
            return 0
        rep = self._scores[to_did]
        before = len(rep.endorsements)
        rep.endorsements = [e for e in rep.endorsements if e.from_did != from_did]
        removed = before - len(rep.endorsements)
        if removed:
            self._recalculate(to_did)
        return removed

    # -- Score access --------------------------------------------------

    def get_score(self, did: str) -> ReputationScore:
        """Get current reputation (applies decay first)."""
        if did not in self._scores:
            return ReputationScore(decay_rate=self.decay_rate)
        self._apply_decay(did)
        return self._scores[did]

    def get_all_scores(self) -> dict[str, ReputationScore]:
        """Return reputation data for all known agents."""
        for did in self._scores:
            self._apply_decay(did)
        return dict(self._scores)

    # -- Internals -----------------------------------------------------

    def _apply_decay(self, did: str) -> None:
        rep = self._scores[did]
        now = time.time()
        days_elapsed = (now - rep.last_updated) / 86400
        if days_elapsed > 0:
            decay_factor = math.exp(-rep.decay_rate * days_elapsed)
            rep.score *= decay_factor
            rep.last_updated = now
            rep.level = _level_for(rep.score)

    def _recalculate(self, did: str) -> None:
        rep = self._scores[did]
        # Sum weighted endorsements, capped
        raw = sum(e.weight for e in rep.endorsements)
        rep.score = min(raw * 10, 100.0)
        rep.level = _level_for(rep.score)
        rep.last_updated = time.time()
