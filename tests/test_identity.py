"""Tests for agent_identity.identity."""

import time

from agent_identity.identity import AgentIdentity


class TestCreation:
    def test_basic_creation(self):
        agent = AgentIdentity(name="test-agent")
        assert agent.name == "test-agent"
        assert agent.agent_id
        assert agent.did.startswith("did:agent:")
        assert agent.created_at > 0

    def test_deterministic_did(self):
        a1 = AgentIdentity(name="x", agent_id="id1", created_at=100.0, _did_seed="seed")
        a2 = AgentIdentity(name="x", agent_id="id1", created_at=100.0, _did_seed="seed")
        assert a1.did == a2.did

    def test_different_seeds_different_dids(self):
        a1 = AgentIdentity(name="a", _did_seed="s1")
        a2 = AgentIdentity(name="b", _did_seed="s2")
        assert a1.did != a2.did

    def test_empty_name_raises(self):
        import pytest
        with pytest.raises(ValueError):
            AgentIdentity(name="")

    def test_custom_metadata(self):
        agent = AgentIdentity(name="m", metadata={"role": "pilot", "version": 2})
        assert agent.metadata["role"] == "pilot"


class TestDIDDocument:
    def test_structure(self):
        agent = AgentIdentity(name="doc-test", public_key="pk123")
        doc = agent.did_document()
        assert doc["id"] == agent.did
        assert doc["@context"][0] == "https://www.w3.org/ns/did/v1"
        assert len(doc["verificationMethod"]) == 1
        vm = doc["verificationMethod"][0]
        assert vm["controller"] == agent.did
        assert vm["publicKeyMultibase"] == "pk123"

    def test_authentication_references(self):
        agent = AgentIdentity(name="auth-test")
        doc = agent.did_document()
        key_ref = f"{agent.did}#key-1"
        assert key_ref in doc["authentication"]
        assert key_ref in doc["assertionMethod"]


class TestSerialization:
    def test_round_trip(self):
        agent = AgentIdentity(
            name="rt", metadata={"k": "v"}, public_key="pk"
        )
        d = agent.to_dict()
        restored = AgentIdentity.from_dict(d)
        assert restored.name == agent.name
        assert restored.agent_id == agent.agent_id
        assert restored.did == agent.did
        assert restored.metadata == agent.metadata
        assert restored.public_key == agent.public_key

    def test_fingerprint_length(self):
        agent = AgentIdentity(name="fp")
        assert len(agent.fingerprint()) == 16

    def test_repr(self):
        agent = AgentIdentity(name="r")
        r = repr(agent)
        assert "AgentIdentity" in r
        assert "r" in r
