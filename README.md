# agent-identity

Cryptographic identity system for fleet agents — unique IDs, reputation, identity verification, and credential management.

Part of the [Cocapn fleet](https://github.com/Lucineer/the-fleet).

## Install

```bash
pip install agent-identity
```

For development:

```bash
pip install -e ".[dev]"
```

## Quick Start

### Create an Identity

```python
from agent_identity import AgentIdentity

agent = AgentIdentity(name="navigator-01", public_key="z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
print(agent.did)           # did:agent:a3f7b2c9...
print(agent.fingerprint()) # a3f7b2c9e4d1f08a
print(agent.did_document())
```

### Reputation System

```python
from agent_identity import ReputationEngine

engine = ReputationEngine()
engine.add_endorsement("did:agent:alice", "did:agent:bob", reason="reliable")
engine.add_endorsement("did:agent:carol", "did:agent:bob", weight=2.0)

score = engine.get_score("did:agent:bob")
print(score.score)  # 30.0
print(score.level)  # <ReputationLevel.SILVER: 'silver'>
```

### Identity Verification

```python
import hashlib
from agent_identity import Verifier

verifier = Verifier()
challenge = verifier.create_challenge(agent.did)

# Agent computes response: sha256(nonce + ":" + did)
response = hashlib.sha256(f"{challenge.nonce}:{agent.did}".encode()).hexdigest()

result = verifier.verify_response(challenge.challenge_id, response)
print(result.verified)  # True
```

### Agent Registry

```python
from agent_identity import AgentIdentity, AgentRegistry

registry = AgentRegistry()
registry.register(agent)
registry.add_alias(agent.did, "nav")

# Resolve by DID, alias, or name
found = registry.resolve("nav")
matches = registry.search_by_name("navigator")
```

### Credential Management

```python
from agent_identity import CredentialStore, CredentialType

store = CredentialStore()
cred = store.add(
    did=agent.did,
    credential_type=CredentialType.API_KEY,
    value="sk-abc123def456",
    label="OpenAI",
)

print(cred.masked_value)  # sk-a**********f456
print(cred.is_valid)      # True

store.revoke(cred.credential_id)
```

## Architecture

| Module | Description |
|---|---|
| `identity.py` | Core `AgentIdentity` class — unique DID, metadata, serialization |
| `reputation.py` | `ReputationEngine` — scoring, decay, endorsements, levels |
| `verification.py` | `Verifier` — challenge-response identity proof |
| `registry.py` | `AgentRegistry` — lookup, aliases, search |
| `credentials.py` | `CredentialStore` — API keys, tokens, certificates |

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -q
```

## License

MIT
