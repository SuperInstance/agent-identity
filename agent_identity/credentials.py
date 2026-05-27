"""Credential management — API keys, tokens, and certificates."""

from __future__ import annotations

import hashlib
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CredentialType(str, Enum):
    API_KEY = "api_key"
    TOKEN = "token"
    CERTIFICATE = "certificate"
    CUSTOM = "custom"


class CredentialStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass
class Credential:
    """A single credential associated with an agent.

    Example::

        cred = Credential(
            did="did:agent:abc123",
            credential_type=CredentialType.API_KEY,
            value="sk-abc123",
        )
    """

    credential_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    did: str = ""
    credential_type: CredentialType = CredentialType.API_KEY
    value: str = ""
    label: str = ""
    status: CredentialStatus = CredentialStatus.ACTIVE
    created_at: float = field(default_factory=time.time)
    expires_at: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    # -- Helpers -------------------------------------------------------

    @property
    def is_valid(self) -> bool:
        if self.status != CredentialStatus.ACTIVE:
            return False
        if self.expires_at is not None and time.time() > self.expires_at:
            return False
        return True

    @property
    def masked_value(self) -> str:
        """Show first 4 and last 4 chars, mask the rest."""
        if len(self.value) <= 8:
            return "****"
        return f"{self.value[:4]}{'*' * (len(self.value) - 8)}{self.value[-4:]}"

    def fingerprint(self) -> str:
        """SHA-256 fingerprint of the credential value."""
        return hashlib.sha256(self.value.encode()).hexdigest()[:16]

    def to_dict(self, include_value: bool = False) -> dict[str, Any]:
        d: dict[str, Any] = {
            "credential_id": self.credential_id,
            "did": self.did,
            "type": self.credential_type.value,
            "label": self.label,
            "status": self.status.value,
            "fingerprint": self.fingerprint(),
            "is_valid": self.is_valid,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }
        if include_value:
            d["value"] = self.value
        return d


class CredentialStore:
    """Manages credentials for multiple agents.

    Example::

        store = CredentialStore()
        cred = store.add(
            did="did:agent:abc123",
            credential_type=CredentialType.API_KEY,
            value="sk-abc123",
            label="OpenAI",
        )
        keys = store.list_for_did("did:agent:abc123")
    """

    def __init__(self) -> None:
        self._credentials: dict[str, Credential] = {}  # id → credential
        self._by_did: dict[str, list[str]] = {}  # did → [cred_ids]

    # -- CRUD ----------------------------------------------------------

    def add(
        self,
        did: str,
        credential_type: CredentialType = CredentialType.API_KEY,
        value: str = "",
        label: str = "",
        expires_at: float | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Credential:
        """Create and store a new credential."""
        cred = Credential(
            did=did,
            credential_type=credential_type,
            value=value or os.urandom(32).hex(),
            label=label,
            expires_at=expires_at,
            metadata=metadata or {},
        )
        self._credentials[cred.credential_id] = cred
        self._by_did.setdefault(did, []).append(cred.credential_id)
        return cred

    def get(self, credential_id: str) -> Credential | None:
        return self._credentials.get(credential_id)

    def revoke(self, credential_id: str) -> bool:
        cred = self._credentials.get(credential_id)
        if cred and cred.status == CredentialStatus.ACTIVE:
            cred.status = CredentialStatus.REVOKED
            return True
        return False

    def delete(self, credential_id: str) -> bool:
        """Permanently remove a credential."""
        cred = self._credentials.pop(credential_id, None)
        if cred:
            ids = self._by_did.get(cred.did, [])
            self._by_did[cred.did] = [i for i in ids if i != credential_id]
            return True
        return False

    # -- Queries -------------------------------------------------------

    def list_for_did(self, did: str) -> list[Credential]:
        ids = self._by_did.get(did, [])
        return [self._credentials[i] for i in ids if i in self._credentials]

    def list_active(self, did: str) -> list[Credential]:
        return [c for c in self.list_for_did(did) if c.is_valid]

    def find_by_type(self, did: str, credential_type: CredentialType) -> list[Credential]:
        return [
            c
            for c in self.list_for_did(did)
            if c.credential_type == credential_type
        ]

    def get_by_label(self, did: str, label: str) -> Credential | None:
        for c in self.list_for_did(did):
            if c.label == label:
                return c
        return None

    # -- Maintenance ---------------------------------------------------

    def expire_passive(self) -> int:
        """Mark credentials past their expiry as expired. Returns count updated."""
        count = 0
        now = time.time()
        for cred in self._credentials.values():
            if (
                cred.status == CredentialStatus.ACTIVE
                and cred.expires_at is not None
                and now > cred.expires_at
            ):
                cred.status = CredentialStatus.EXPIRED
                count += 1
        return count

    @property
    def total_count(self) -> int:
        return len(self._credentials)
