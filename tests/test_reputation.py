"""Tests for agent_identity.reputation."""

from agent_identity.reputation import ReputationEngine, ReputationLevel


class TestReputationEngine:
    def test_new_agent_has_zero(self):
        engine = ReputationEngine()
        score = engine.get_score("did:agent:new")
        assert score.score == 0.0
        assert score.level == ReputationLevel.NEW

    def test_endorsement_increases_score(self):
        engine = ReputationEngine()
        engine.add_endorsement("did:a", "did:b")
        score = engine.get_score("did:b")
        assert score.score >= 9.9
        assert score.level == ReputationLevel.NEW  # <20 threshold

    def test_multiple_endorsements(self):
        engine = ReputationEngine()
        engine.add_endorsement("did:a", "did:c")
        engine.add_endorsement("did:b", "did:c")
        engine.add_endorsement("did:d", "did:c", weight=2.0)
        score = engine.get_score("did:c")
        assert score.score >= 39.9

    def test_score_cap_at_100(self):
        engine = ReputationEngine()
        for i in range(15):
            engine.add_endorsement(f"did:x{i}", "did:cap")
        score = engine.get_score("did:cap")
        assert score.score >= 99.9
        assert score.score <= 100.0

    def test_level_progression(self):
        engine = ReputationEngine()
        # 1 endorsement = 10 pts → NEW (<20)
        engine.add_endorsement("did:a", "did:lvl")
        assert engine.get_score("did:lvl").level == ReputationLevel.NEW

        # 3 more = 40 pts → SILVER (>=50? no, 40 → BRONZE)
        for i in range(3):
            engine.add_endorsement(f"did:b{i}", "did:lvl")
        assert engine.get_score("did:lvl").level == ReputationLevel.BRONZE

        # 4 more = 80 pts → GOLD (>=70)
        for i in range(4):
            engine.add_endorsement(f"did:c{i}", "did:lvl")
        assert engine.get_score("did:lvl").level == ReputationLevel.GOLD

        # 2 more = 100 pts → PLATINUM (>=90)
        for i in range(2):
            engine.add_endorsement(f"did:d{i}", "did:lvl")
        assert engine.get_score("did:lvl").level == ReputationLevel.PLATINUM

    def test_remove_endorsement(self):
        engine = ReputationEngine()
        engine.add_endorsement("did:a", "did:rem")
        assert engine.get_score("did:rem").score >= 9.9

        removed = engine.remove_endorsements_from("did:a", "did:rem")
        assert removed == 1
        assert engine.get_score("did:rem").score == 0.0

    def test_remove_nonexistent(self):
        engine = ReputationEngine()
        assert engine.remove_endorsements_from("did:ghost", "did:ghost2") == 0

    def test_weighted_endorsement(self):
        engine = ReputationEngine()
        engine.add_endorsement("did:a", "did:w", weight=5.0)
        score = engine.get_score("did:w")
        assert score.score >= 49.9

    def test_endorsement_with_reason(self):
        engine = ReputationEngine()
        e = engine.add_endorsement("did:a", "did:r", reason="reliable")
        assert e.reason == "reliable"

    def test_get_all_scores(self):
        engine = ReputationEngine()
        engine.add_endorsement("did:a", "did:s1")
        engine.add_endorsement("did:b", "did:s2")
        all_scores = engine.get_all_scores()
        assert "did:s1" in all_scores
        assert "did:s2" in all_scores

    def test_score_to_dict(self):
        engine = ReputationEngine()
        engine.add_endorsement("did:a", "did:dict")
        d = engine.get_score("did:dict").to_dict()
        assert "score" in d
        assert "level" in d
        assert d["level"] == "new"  # 10 pts → NEW
