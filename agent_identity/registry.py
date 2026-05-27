"""Agent registry — lookup, search, and alias management."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_identity.identity import AgentIdentity


@dataclass
class Alias:
    """An alternative name / DID alias for an agent."""

    alias: str
    did: str
    created_at: float = 0.0


class AgentRegistry:
    """In-memory registry for looking up agents by DID, name, or alias.

    Supports:
    - Register / deregister agents
    - Alias management (multiple names per agent)
    - Search by name (substring match) or metadata key/value
    - Bulk listing

    Example::

        registry = AgentRegistry()
        agent = AgentIdentity(name="navigator-01")
        registry.register(agent)
        found = registry.get_by_did(agent.did)
        assert found.name == "navigator-01"
    """

    def __init__(self) -> None:
        self._by_did: dict[str, AgentIdentity] = {}
        self._aliases: dict[str, str] = {}  # alias → did

    # -- Register / remove ---------------------------------------------

    def register(self, agent: AgentIdentity) -> None:
        """Register an agent. Overwrites if DID already exists."""
        self._by_did[agent.did] = agent

    def deregister(self, did: str) -> bool:
        """Remove an agent by DID. Returns True if it existed."""
        if did in self._by_did:
            del self._by_did[did]
            # Clean up aliases pointing to this DID
            self._aliases = {a: d for a, d in self._aliases.items() if d != did}
            return True
        return False

    # -- Aliases -------------------------------------------------------

    def add_alias(self, did: str, alias: str) -> bool:
        """Add an alias for a registered agent. Returns False if DID not found."""
        if did not in self._by_did:
            return False
        self._aliases[alias] = did
        return True

    def remove_alias(self, alias: str) -> bool:
        if alias in self._aliases:
            del self._aliases[alias]
            return True
        return False

    def get_aliases(self, did: str) -> list[str]:
        return [a for a, d in self._aliases.items() if d == did]

    # -- Lookups -------------------------------------------------------

    def get_by_did(self, did: str) -> AgentIdentity | None:
        return self._by_did.get(did)

    def get_by_name(self, name: str) -> list[AgentIdentity]:
        return [a for a in self._by_did.values() if a.name == name]

    def get_by_alias(self, alias: str) -> AgentIdentity | None:
        did = self._aliases.get(alias)
        if did:
            return self._by_did.get(did)
        return None

    def resolve(self, identifier: str) -> AgentIdentity | None:
        """Resolve by DID, alias, or exact name (in that priority)."""
        agent = self.get_by_did(identifier)
        if agent:
            return agent
        agent = self.get_by_alias(identifier)
        if agent:
            return agent
        matches = self.get_by_name(identifier)
        return matches[0] if matches else None

    # -- Search --------------------------------------------------------

    def search_by_name(self, query: str) -> list[AgentIdentity]:
        """Case-insensitive substring search on agent names."""
        q = query.lower()
        return [a for a in self._by_did.values() if q in a.name.lower()]

    def search_by_metadata(self, key: str, value: Any | None = None) -> list[AgentIdentity]:
        """Find agents that have a metadata key (optionally matching a value)."""
        results: list[AgentIdentity] = []
        for a in self._by_did.values():
            if key in a.metadata:
                if value is None or a.metadata[key] == value:
                    results.append(a)
        return results

    # -- Listing -------------------------------------------------------

    def list_all(self) -> list[AgentIdentity]:
        return list(self._by_did.values())

    @property
    def size(self) -> int:
        return len(self._by_did)

    # -- Import / export -----------------------------------------------

    def to_dict_list(self) -> list[dict[str, Any]]:
        return [a.to_dict() for a in self._by_did.values()]

    def load_dict_list(self, items: list[dict[str, Any]]) -> int:
        """Bulk-register agents from a list of dicts. Returns count loaded."""
        count = 0
        for item in items:
            try:
                self.register(AgentIdentity.from_dict(item))
                count += 1
            except (KeyError, ValueError):
                continue
        return count
