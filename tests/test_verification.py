"""Tests for agent_identity.verification."""

import hashlib

from agent_identity.verification import ChallengeStatus, Verifier


class TestVerifier:
    def test_create_challenge(self):
        v = Verifier()
        ch = v.create_challenge("did:agent:abc")
        assert ch.did == "did:agent:abc"
        assert ch.status == ChallengeStatus.PENDING
        assert ch.nonce
        assert ch.expected_response

    def test_successful_verification(self):
        v = Verifier()
        did = "did:agent:test"
        ch = v.create_challenge(did)
        response = hashlib.sha256(f"{ch.nonce}:{did}".encode()).hexdigest()
        result = v.verify_response(ch.challenge_id, response)
        assert result.verified
        assert result.reason == "Signature matched"
        assert ch.status == ChallengeStatus.VERIFIED

    def test_failed_verification(self):
        v = Verifier()
        ch = v.create_challenge("did:agent:fail")
        result = v.verify_response(ch.challenge_id, "wrong")
        assert not result.verified
        assert ch.status == ChallengeStatus.FAILED

    def test_unknown_challenge(self):
        v = Verifier()
        result = v.verify_response("nonexistent", "x")
        assert not result.verified
        assert "not found" in result.reason

    def test_already_used_challenge(self):
        v = Verifier()
        did = "did:agent:reuse"
        ch = v.create_challenge(did)
        resp = hashlib.sha256(f"{ch.nonce}:{did}".encode()).hexdigest()
        v.verify_response(ch.challenge_id, resp)
        result = v.verify_response(ch.challenge_id, resp)
        assert not result.verified
        assert "already" in result.reason

    def test_list_results(self):
        v = Verifier()
        ch = v.create_challenge("did:agent:res")
        v.verify_response(ch.challenge_id, "wrong")
        results = v.list_results()
        assert len(results) == 1
        results_filtered = v.list_results(did="did:agent:res")
        assert len(results_filtered) == 1
        results_other = v.list_results(did="did:agent:other")
        assert len(results_other) == 0

    def test_challenge_to_dict(self):
        v = Verifier()
        ch = v.create_challenge("did:agent:d")
        d = ch.to_dict()
        assert d["did"] == "did:agent:d"
        assert d["status"] == "pending"

    def test_cleanup_expired(self):
        v = Verifier(challenge_ttl=-1)  # instantly expired
        ch = v.create_challenge("did:agent:exp")
        removed = v.cleanup_expired()
        assert removed == 1

    def test_no_cleanup_on_active(self):
        v = Verifier(challenge_ttl=3600)
        v.create_challenge("did:agent:active")
        removed = v.cleanup_expired()
        assert removed == 0
