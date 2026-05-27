"""Tests for agent_identity.registry."""

from agent_identity.identity import AgentIdentity
from agent_identity.registry import AgentRegistry


def _make(name: str, **kw) -> AgentIdentity:
    return AgentIdentity(name=name, **kw)


class TestRegistry:
    def test_register_and_get(self):
        r = AgentRegistry()
        a = _make("nav-01")
        r.register(a)
        assert r.get_by_did(a.did) is a
        assert r.size == 1

    def test_deregister(self):
        r = AgentRegistry()
        a = _make("x")
        r.register(a)
        assert r.deregister(a.did) is True
        assert r.get_by_did(a.did) is None
        assert r.deregister(a.did) is False

    def test_get_by_name(self):
        r = AgentRegistry()
        a1 = _make("alpha")
        a2 = _make("beta")
        a3 = _make("alpha")
        r.register(a1)
        r.register(a2)
        r.register(a3)
        matches = r.get_by_name("alpha")
        assert len(matches) == 2

    def test_aliases(self):
        r = AgentRegistry()
        a = _make("aliased")
        r.register(a)
        assert r.add_alias(a.did, "alias-1") is True
        assert r.add_alias("did:fake", "nope") is False
        found = r.get_by_alias("alias-1")
        assert found is a
        aliases = r.get_aliases(a.did)
        assert "alias-1" in aliases
        r.remove_alias("alias-1")
        assert r.get_by_alias("alias-1") is None

    def test_resolve(self):
        r = AgentRegistry()
        a = _make("resolver")
        r.register(a)
        r.add_alias(a.did, "my-alias")
        assert r.resolve(a.did) is a
        assert r.resolve("my-alias") is a
        assert r.resolve("resolver") is a
        assert r.resolve("nonexistent") is None

    def test_search_by_name(self):
        r = AgentRegistry()
        r.register(_make("navigator-alpha"))
        r.register(_make("navigator-beta"))
        r.register(_make("pilot-01"))
        results = r.search_by_name("navigator")
        assert len(results) == 2
        results = r.search_by_name("NAV")
        assert len(results) == 2

    def test_search_by_metadata(self):
        r = AgentRegistry()
        r.register(_make("m1", metadata={"team": "red"}))
        r.register(_make("m2", metadata={"team": "blue"}))
        r.register(_make("m3", metadata={"team": "red"}))
        assert len(r.search_by_metadata("team")) == 3
        assert len(r.search_by_metadata("team", "red")) == 2

    def test_deregister_cleans_aliases(self):
        r = AgentRegistry()
        a = _make("clean")
        r.register(a)
        r.add_alias(a.did, "gone")
        r.deregister(a.did)
        assert r.get_by_alias("gone") is None

    def test_to_dict_list_round_trip(self):
        r = AgentRegistry()
        a1 = _make("exp1", metadata={"k": 1})
        a2 = _make("exp2", metadata={"k": 2})
        r.register(a1)
        r.register(a2)
        dicts = r.to_dict_list()
        r2 = AgentRegistry()
        loaded = r2.load_dict_list(dicts)
        assert loaded == 2
        assert r2.size == 2

    def test_list_all(self):
        r = AgentRegistry()
        for i in range(5):
            r.register(_make(f"agent-{i}"))
        assert len(r.list_all()) == 5
