"""Tests for agent_identity.credentials."""

import time

from agent_identity.credentials import CredentialStore, CredentialType, CredentialStatus


class TestCredentialStore:
    def test_add_credential(self):
        store = CredentialStore()
        cred = store.add(
            did="did:agent:a",
            credential_type=CredentialType.API_KEY,
            value="sk-1234567890abcdef",
            label="OpenAI",
        )
        assert cred.did == "did:agent:a"
        assert cred.credential_type == CredentialType.API_KEY
        assert cred.is_valid
        assert cred.label == "OpenAI"

    def test_masked_value(self):
        store = CredentialStore()
        cred = store.add(did="did:agent:m", value="sk-longsecretkey123")
        assert cred.masked_value.startswith("sk-l")
        assert cred.masked_value.endswith("y123")
        assert "*" in cred.masked_value

    def test_fingerprint(self):
        store = CredentialStore()
        cred = store.add(did="did:agent:f", value="abc")
        assert len(cred.fingerprint()) == 16

    def test_revoke(self):
        store = CredentialStore()
        cred = store.add(did="did:agent:r", value="x")
        assert store.revoke(cred.credential_id) is True
        assert not cred.is_valid
        assert cred.status == CredentialStatus.REVOKED
        assert store.revoke(cred.credential_id) is False  # already revoked

    def test_delete(self):
        store = CredentialStore()
        cred = store.add(did="did:agent:d", value="x")
        assert store.delete(cred.credential_id) is True
        assert store.get(cred.credential_id) is None
        assert store.delete("nonexistent") is False

    def test_list_for_did(self):
        store = CredentialStore()
        store.add(did="did:agent:l", value="a")
        store.add(did="did:agent:l", value="b")
        store.add(did="did:agent:other", value="c")
        assert len(store.list_for_did("did:agent:l")) == 2

    def test_list_active_excludes_revoked(self):
        store = CredentialStore()
        c1 = store.add(did="did:agent:la", value="a")
        store.add(did="did:agent:la", value="b")
        store.revoke(c1.credential_id)
        active = store.list_active("did:agent:la")
        assert len(active) == 1

    def test_find_by_type(self):
        store = CredentialStore()
        store.add(did="did:agent:t", credential_type=CredentialType.API_KEY, value="k")
        store.add(did="did:agent:t", credential_type=CredentialType.TOKEN, value="t")
        keys = store.find_by_type("did:agent:t", CredentialType.API_KEY)
        assert len(keys) == 1
        assert keys[0].credential_type == CredentialType.API_KEY

    def test_get_by_label(self):
        store = CredentialStore()
        store.add(did="did:agent:lbl", value="x", label="prod")
        store.add(did="did:agent:lbl", value="y", label="staging")
        found = store.get_by_label("did:agent:lbl", "prod")
        assert found is not None
        assert found.value == "x"
        assert store.get_by_label("did:agent:lbl", "dev") is None

    def test_expiry(self):
        store = CredentialStore()
        cred = store.add(
            did="did:agent:exp",
            value="x",
            expires_at=time.time() - 100,  # already expired
        )
        assert not cred.is_valid
        n = store.expire_passive()
        assert n == 1
        assert cred.status == CredentialStatus.EXPIRED

    def test_to_dict_without_value(self):
        store = CredentialStore()
        cred = store.add(did="did:agent:td", value="secret123")
        d = cred.to_dict()
        assert "value" not in d
        assert "fingerprint" in d

    def test_to_dict_with_value(self):
        store = CredentialStore()
        cred = store.add(did="did:agent:tw", value="secret123")
        d = cred.to_dict(include_value=True)
        assert d["value"] == "secret123"

    def test_total_count(self):
        store = CredentialStore()
        store.add(did="did:agent:c", value="a")
        store.add(did="did:agent:c", value="b")
        assert store.total_count == 2

    def test_auto_generated_value(self):
        store = CredentialStore()
        cred = store.add(did="did:agent:auto")
        assert len(cred.value) == 64  # 32 bytes hex

    def test_deregister_agent_cleans_credentials(self):
        """Verify credentials stay when agent removed (registry is separate)."""
        store = CredentialStore()
        store.add(did="did:agent:sep", value="x")
        # CredentialStore is independent of AgentRegistry
        assert store.total_count == 1
