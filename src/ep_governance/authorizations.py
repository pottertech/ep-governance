"""EP-Governance authorization token engine — Ed25519 signed tokens.

This module implements the Phase 4 authorization lifecycle:

  - :class:`KeyManager` wraps an Ed25519 keypair (PyNaCl).  The EP holds
    the private signing key; proxies receive only the public verification
    key.
  - :class:`AuthorizationToken` is a dataclass carrying the 14 directive
    fields (section 17).  It can produce a canonical payload, sign it, and
    verify a signature.
  - :class:`AuthorizationEngine` orchestrates token issuance, atomic
    claiming, staleness detection, and standalone token verification.

Design constraints:
  - Tokens are short-lived (default 5 minutes), single-use, and bound to
    agent, project, branch, proxy audience, payload, and policy set.
  - The database stores a SHA-256 *hash* of the signed token, never the
    reusable token itself (EP-AUTH-008).
  - Claiming is an atomic ``UPDATE ... WHERE used = FALSE ... RETURNING``
    operation (EP-AUTH-009/010).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import sqlalchemy as sa

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection

from nacl.encoding import RawEncoder
from nacl.signing import SigningKey, VerifyKey

from .canonical import canonical_hash, canonical_json, canonical_json_bytes, compute_policy_set_hash
from .db.repositories import AuthorizationRepository, TransitionRepository
from .db.transactions import transaction
from .deployment import EnforcementCapability, EnforcementUnavailableError
from .errors import (
    TokenInvalidError,
)
from .xid import XID

__all__ = [
    "KeyManager",
    "AuthorizationToken",
    "AdvisoryDecision",
    "AuthorizationEngine",
]

# Default token time-to-live in seconds (5 minutes, per EP-AUTH-001).
DEFAULT_TOKEN_TTL_SECONDS: int = 300


# --------------------------------------------------------------------------- #
# KeyManager
# --------------------------------------------------------------------------- #


class KeyManager:
    """Manage an Ed25519 signing/verification keypair.

    The private key (``SigningKey``) is kept by the EP and **never** shared
    with proxies or agents.  The public key (``VerifyKey``) is shared with
    proxies so they can verify token signatures without being able to mint
    new tokens.

    Example::

        km = KeyManager()
        km.save_private_key("/var/lib/ep-governance/ep_signing.key")

        # Later, in a different process:
        km2 = KeyManager()
        km2.load_private_key("/var/lib/ep-governance/ep_signing.key")
    """

    def __init__(self) -> None:
        """Generate a new Ed25519 keypair."""
        self._signing_key: SigningKey = SigningKey.generate()

    # ------------------------------------------------------------------ #
    # Accessors
    # ------------------------------------------------------------------ #

    @property
    def private_key(self) -> SigningKey:
        """Return the Ed25519 signing key (EP only, never shared)."""
        return self._signing_key

    @property
    def public_key(self) -> VerifyKey:
        """Return the Ed25519 verification key (shared with proxies)."""
        return self._signing_key.verify_key

    # ------------------------------------------------------------------ #
    # Serialization
    # ------------------------------------------------------------------ #

    def save_private_key(self, path: str) -> None:
        """Serialize the private key to *path* as raw 32 bytes.

        The file is written with mode ``0600`` to restrict read access.
        Callers should ensure the parent directory has appropriate
        permissions.
        """
        raw = self._signing_key.encode(encoder=RawEncoder)
        # Write with restrictive permissions where the OS supports it.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, raw)
        finally:
            os.close(fd)

    def load_private_key(self, path: str) -> None:
        """Load a private key from *path* (raw 32-byte file).

        Raises:
            TokenInvalidError: if the file does not contain exactly 32 bytes.
        """
        with open(path, "rb") as fh:
            raw = fh.read()
        if len(raw) != 32:
            raise TokenInvalidError(
                f"Private key file '{path}' must contain 32 bytes, got {len(raw)}"
            )
        self._signing_key = SigningKey(raw, encoder=RawEncoder)

    @classmethod
    def from_private_key(cls, private_key_bytes: bytes) -> KeyManager:
        """Create a :class:`KeyManager` from existing raw key bytes.

        Args:
            private_key_bytes: 32 raw bytes of an Ed25519 signing key.

        Raises:
            TokenInvalidError: if the input is not exactly 32 bytes.
        """
        if len(private_key_bytes) != 32:
            raise TokenInvalidError(f"Private key must be 32 bytes, got {len(private_key_bytes)}")
        km = cls.__new__(cls)  # bypass __init__ key generation
        km._signing_key = SigningKey(private_key_bytes, encoder=RawEncoder)
        return km


# --------------------------------------------------------------------------- #
# AuthorizationToken dataclass
# --------------------------------------------------------------------------- #


@dataclass
class AuthorizationToken:
    """An Ed25519-signed authorization token (directive section 17).

    Fields:
        authorization_id:      XID identifying this authorization.
        transition_id:         The transition this token authorizes.
        agent_id:              The agent permitted to use this token.
        project_id:            The project the action targets.
        branch_id:             The branch the action targets.
        proxy_audience:        The proxy audience this token is valid for.
        tool:                  The tool the agent is authorized to invoke.
        payload_hash:          SHA-256 hash of the canonical action payload.
        policy_set_hash:       SHA-256 hash of the effective policy set.
        matched_policy_versions: Mapping of policy XID → version integer.
        issued_at:             ISO 8601 UTC timestamp (issue time).
        expires_at:            ISO 8601 UTC timestamp (expiry).
        nonce:                 Random hex nonce (32 bytes, hex-encoded).
        signature:             Ed25519 signature (hex) over the canonical
                               payload; empty until signed.
    """

    authorization_id: str
    transition_id: str
    agent_id: str
    project_id: str
    branch_id: str
    proxy_audience: str
    tool: str
    payload_hash: str
    policy_set_hash: str
    matched_policy_versions: dict[str, int]
    issued_at: str
    expires_at: str
    nonce: str
    signature: str = ""

    # ------------------------------------------------------------------ #
    # Canonicalization / signing
    # ------------------------------------------------------------------ #

    def to_canonical_payload(self) -> dict[str, Any]:
        """Return all fields *except* ``signature`` as a plain dict.

        This dict is canonicalized (sorted keys, compact JSON) before
        signing or verification so that the signature is deterministic
        and independent of dict insertion order.
        """
        return {
            "authorization_id": self.authorization_id,
            "transition_id": self.transition_id,
            "agent_id": self.agent_id,
            "project_id": self.project_id,
            "branch_id": self.branch_id,
            "proxy_audience": self.proxy_audience,
            "tool": self.tool,
            "payload_hash": self.payload_hash,
            "policy_set_hash": self.policy_set_hash,
            "matched_policy_versions": self.matched_policy_versions,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
        }

    def to_signed_token(self, key_manager: KeyManager) -> str:
        """Sign the canonical payload and return the full token as JSON.

        The returned JSON string contains all 14 fields (the canonical
        payload fields plus ``signature``).  The signature is an Ed25519
        signature over ``canonical_json(canonical_payload)`` encoded as
        UTF-8, hex-encoded in the JSON.

        Args:
            key_manager: The :class:`KeyManager` whose private key signs.

        Returns:
            A JSON string representing the fully-signed token.
        """
        payload = self.to_canonical_payload()
        message = canonical_json_bytes(payload)
        signed = key_manager.private_key.sign(message)
        # signed.signature is the raw 64-byte Ed25519 signature.
        self.signature = signed.signature.hex()
        # Return the full token (payload + signature) as canonical JSON.
        full = {**payload, "signature": self.signature}
        return canonical_json(full)

    def verify_signature(self, public_key: VerifyKey) -> bool:
        """Verify the Ed25519 signature against the canonical payload.

        Args:
            public_key: The EP's :class:`VerifyKey` held by the proxy.

        Returns:
            ``True`` if the signature is valid, ``False`` otherwise.
        """
        if not self.signature:
            return False
        payload = self.to_canonical_payload()
        message = canonical_json_bytes(payload)
        try:
            public_key.verify(message, bytes.fromhex(self.signature))
            return True
        except Exception:
            return False


# --------------------------------------------------------------------------- #
# AdvisoryDecision dataclass
# --------------------------------------------------------------------------- #


@dataclass
class AdvisoryDecision:
    """A non-executable advisory decision record.

    This is returned by :meth:`AuthorizationEngine.record_advisory_decision`
    when binding enforcement is not active (advisory mode). An
    ``AdvisoryDecision`` is structurally distinct from an
    :class:`AuthorizationToken` — it carries no signature, no nonce, and
    cannot be claimed or executed by any proxy. A proxy must never accept
    an ``AdvisoryDecision`` in place of a signed ``AuthorizationToken``.

    Fields:
        decision_id:     XID identifying this advisory decision.
        transition_id:   The transition this decision covers.
        agent_id:        The agent that requested the action.
        project_id:      The project being acted upon.
        branch_id:       The branch being acted upon.
        tool:            The tool that was evaluated.
        payload_hash:    SHA-256 hash of the canonical action payload.
        policy_set_hash: SHA-256 hash of the effective policy set.
        matched_policy_versions: Mapping of policy XID → version integer.
        created_at:      ISO 8601 UTC timestamp.
        advisory:        Always ``True`` — markers that this is advisory.
    """

    decision_id: str
    transition_id: str
    agent_id: str
    project_id: str
    branch_id: str
    tool: str
    payload_hash: str
    policy_set_hash: str
    matched_policy_versions: dict[str, int]
    created_at: str
    advisory: bool = True


# --------------------------------------------------------------------------- #
# AuthorizationEngine
# --------------------------------------------------------------------------- #


class AuthorizationEngine:
    """Orchestrate authorization token issuance, claiming, and verification.

    The engine sits between the policy engine (which determines whether an
    action is allowed) and the proxy (which executes the action on behalf
    of an agent).  It is initialized with a database connection, the EP's
    :class:`KeyManager`, and the EP's service principal ID.
    """

    def __init__(
        self,
        engine: sa.Engine,
        key_manager: KeyManager,
        ep_service_principal_id: str,
        token_ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS,
    ) -> None:
        """Initialize the engine.

        Args:
            engine:                  A SQLAlchemy ``Engine``.
            key_manager:           The EP's :class:`KeyManager`.
            ep_service_principal_id: XID of the EP service principal.
            token_ttl_seconds:     Token lifetime (default 300 = 5 min).
        """
        self.engine = engine
        self.key_manager = key_manager
        self.ep_service_principal_id = ep_service_principal_id
        self.token_ttl_seconds = token_ttl_seconds

    # ------------------------------------------------------------------ #
    # Issuance
    # ------------------------------------------------------------------ #

    def issue_authorization(
        self,
        transition_id: str,
        agent_id: str,
        project_id: str,
        branch_id: str,
        proxy_audience: str,
        tool: str,
        payload_hash: str,
        matched_policies: list[dict[str, Any]],
        enforcement_capability: EnforcementCapability,
    ) -> AuthorizationToken:
        """Issue a new signed authorization token.

        Args:
            transition_id:    The transition this authorization covers.
            agent_id:          The agent permitted to execute.
            project_id:        The project being acted upon.
            branch_id:         The branch being acted upon.
            proxy_audience:    The target proxy audience (e.g. ``"github"``).
            tool:              The tool to invoke.
            payload_hash:      SHA-256 of the canonical action payload.
            matched_policies:  List of policy dicts that matched the action.
                               Each dict should contain at least ``id`` and
                               ``activation_version`` (or ``version``).
            enforcement_capability: **Required.** An :class:`EnforcementCapability`
                               from :func:`verify_deployment`. The capability
                               must have binding enforcement active, and its
                               ``agent_principal_id`` must match ``agent_id``.
                               This ensures authorization issuance only happens
                               when binding enforcement is verified active AND
                               the capability is bound to the same agent that
                               the token is being issued for.

        Returns:
            A signed :class:`AuthorizationToken`.  The caller passes this
            to the agent, who passes it to the proxy.

        Raises:
            EnforcementUnavailableError: If binding enforcement is not active
                or if the capability's agent_principal_id does not match
                agent_id.
        """
        # --- Enforcement capability checks (Finding 1 + Finding 3) -------
        # The capability is MANDATORY. No default, no optional bypass.
        # 1a. Require binding enforcement to be active.
        enforcement_capability.require_binding_enforcement()

        # 1b. Identity binding.
        #     For agent-scoped capabilities: the capability's
        #     agent_principal_id must match the agent_id being issued
        #     the token. This prevents a capability for Agent A from
        #     being used to issue a token for Agent B.
        #
        #     For proxy-scoped capabilities: the capability attests that
        #     the proxy deployment provides binding enforcement. The EP
        #     service uses this capability to issue tokens on behalf of
        #     any agent whose action has been policy-approved. The proxy
        #     scope is validated (proxy_scoped=True, proxy_audience set,
        #     supports the requested tool) instead of requiring a literal
        #     agent ID match.
        if not enforcement_capability.proxy_scoped:
            # Agent-scoped: require exact agent identity match.
            if enforcement_capability.agent_principal_id != agent_id:
                raise EnforcementUnavailableError(
                    f"Capability agent_principal_id "
                    f"({enforcement_capability.agent_principal_id}) does not match "
                    f"authorization agent_id ({agent_id}). The capability must be "
                    f"bound to the same agent that the token is issued for."
                )
        else:
            # Proxy-scoped: validate the proxy scope is properly configured.
            # The capability must have proxy_audience and support the tool.
            enforcement_capability.require_proxy_scoped()
            # The capability's proxy_audience must match the token's audience.
            if enforcement_capability.proxy_audience != proxy_audience:
                raise EnforcementUnavailableError(
                    f"Capability proxy_audience "
                    f"({enforcement_capability.proxy_audience}) does not match "
                    f"authorization proxy_audience ({proxy_audience})."
                )
            if not enforcement_capability.supports_action_type(tool):
                raise EnforcementUnavailableError(
                    f"Proxy-scoped capability does not support tool '{tool}'. "
                    f"Supported types: {enforcement_capability.supported_action_types}"
                )

        # 1. Generate identifiers and nonce.
        authorization_id = str(XID.new())
        nonce = os.urandom(32).hex()

        # 2. Build matched_policy_versions: policy XID → version integer.
        matched_policy_versions: dict[str, int] = {}
        for policy in matched_policies:
            pid = policy.get("id") or policy.get("policy_id")
            if pid is None:
                continue
            version = policy.get("activation_version")
            if version is None:
                version = policy.get("version", 0)
            matched_policy_versions[str(pid)] = int(version)

        # 3. Compute policy_set_hash from sorted list of (id, version).
        policy_set_hash = compute_policy_set_hash(matched_policy_versions)

        # 4. Timestamps: ISO 8601 UTC with microseconds + Z.
        now = datetime.now(UTC)
        issued_at = now.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        expires_dt = now + timedelta(seconds=self.token_ttl_seconds)
        expires_at = expires_dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"

        # 5. Build the token and sign it.
        token = AuthorizationToken(
            authorization_id=authorization_id,
            transition_id=transition_id,
            agent_id=agent_id,
            project_id=project_id,
            branch_id=branch_id,
            proxy_audience=proxy_audience,
            tool=tool,
            payload_hash=payload_hash,
            policy_set_hash=policy_set_hash,
            matched_policy_versions=matched_policy_versions,
            issued_at=issued_at,
            expires_at=expires_at,
            nonce=nonce,
            signature="",
        )
        signed_token_json = token.to_signed_token(self.key_manager)

        # 6. Compute token hash (SHA-256 of signed token JSON).
        token_hash = hashlib.sha256(signed_token_json.encode("utf-8")).hexdigest()

        # 7. Persist to ep_authorizations via the repository.
        with self.engine.connect() as conn, transaction(conn):
            auth_repo = AuthorizationRepository(conn)
            auth_repo.insert_authorization(
                {
                    "id": authorization_id,
                    "transition_id": transition_id,
                    "agent_id": agent_id,
                    "project_id": project_id,
                    "branch_id": branch_id,
                    "proxy_audience": proxy_audience,
                    "tool": tool,
                    "payload_hash": payload_hash,
                    "policy_set_hash": policy_set_hash,
                    "token_hash": token_hash,
                    "matched_policy_versions": matched_policy_versions,
                    "issued_at": issued_at,
                    "expires_at": expires_at,
                    "nonce": nonce,
                }
            )

        # 8. Return the signed token for the agent → proxy handoff.
        return token

    def record_advisory_decision(
        self,
        transition_id: str,
        agent_id: str,
        project_id: str,
        branch_id: str,
        tool: str,
        payload_hash: str,
        matched_policies: list[dict[str, Any]],
    ) -> AdvisoryDecision:
        """Record a non-executable advisory decision.

        This is the advisory-mode counterpart to :meth:`issue_authorization`.
        It does NOT create a signed token, does NOT interact with the
        authorization table, and the returned :class:`AdvisoryDecision`
        cannot be claimed or executed by any proxy.

        Use this when binding enforcement is not active (advisory mode).
        A proxy must never accept an ``AdvisoryDecision`` in place of a
        signed ``AuthorizationToken``.

        Args:
            transition_id:    The transition this decision covers.
            agent_id:          The agent that requested the action.
            project_id:        The project being acted upon.
            branch_id:         The branch being acted upon.
            tool:              The tool that was evaluated.
            payload_hash:      SHA-256 of the canonical action payload.
            matched_policies:  List of policy dicts that matched.

        Returns:
            An :class:`AdvisoryDecision` record (non-executable).
        """
        decision_id = str(XID.new())

        matched_policy_versions: dict[str, int] = {}
        for policy in matched_policies:
            pid = policy.get("id") or policy.get("policy_id")
            if pid is None:
                continue
            version = policy.get("activation_version")
            if version is None:
                version = policy.get("version", 0)
            matched_policy_versions[str(pid)] = int(version)

        policy_set_hash = compute_policy_set_hash(matched_policy_versions)
        now = datetime.now(UTC)
        created_at = now.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"

        return AdvisoryDecision(
            decision_id=decision_id,
            transition_id=transition_id,
            agent_id=agent_id,
            project_id=project_id,
            branch_id=branch_id,
            tool=tool,
            payload_hash=payload_hash,
            policy_set_hash=policy_set_hash,
            matched_policy_versions=matched_policy_versions,
            created_at=created_at,
            advisory=True,
        )

    # ------------------------------------------------------------------ #
    # Lookup
    # ------------------------------------------------------------------ #

    def get_authorization(self, authorization_id: str) -> dict[str, Any] | None:
        """Return the stored authorization record by ID, or None.

        Delegates to :meth:`AuthorizationRepository.get_authorization`.
        """
        with self.engine.connect() as conn:
            auth_repo = AuthorizationRepository(conn)
            return auth_repo.get_authorization(authorization_id)

    # ------------------------------------------------------------------ #
    # Verification + atomic claim
    # ------------------------------------------------------------------ #

    def verify_and_claim(
        self,
        authorization_id: str,
        signed_token: str,
        payload_hash: str,
        proxy_principal_id: str,
        public_key: VerifyKey,
    ) -> dict[str, Any] | None:
        """Verify a token signature, payload hash, and atomically claim it.

        This is a convenience wrapper that opens its **own** connection and
        transaction.  Callers that already hold a transaction (e.g. a
        ``serializable_transaction`` in the proxy) should call
        :meth:`verify_and_claim_in_transaction` instead, passing their
        existing connection, so that policy revalidation and token claim
        share the same transaction (TOCTOU fix).

        See :meth:`verify_and_claim_in_transaction` for the full step-by-step
        description.
        """
        with self.engine.connect() as conn, transaction(conn):
            return self.verify_and_claim_in_transaction(
                conn,
                authorization_id,
                signed_token,
                payload_hash,
                proxy_principal_id,
                public_key,
            )

    def verify_and_claim_in_transaction(
        self,
        conn: Connection,
        authorization_id: str,
        signed_token: str,
        payload_hash: str,
        proxy_principal_id: str,
        public_key: VerifyKey,
    ) -> dict[str, Any] | None:
        """Verify a token signature, payload hash, and atomically claim it.

        This variant accepts a caller-supplied connection so the claim can
        participate in the caller's existing transaction (e.g. the proxy's
        ``serializable_transaction``).  It does **not** open its own
        connection or top-level transaction — the caller owns those.  A
        SAVEPOINT (``conn.begin_nested()``) is still used for the
        claim-and-transition-advancement so a failed advancement rolls back
        only the claim, not the caller's entire transaction.

        The proxy:
          1. Parses and verifies the token signature using the EP public key.
          2. Confirms the payload hash matches the authorized one.
          3. Computes the SHA-256 hash of the presented signed token and
             compares it to the ``token_hash`` stored in the database
             authorization record (EP-AUTH-008).  If they differ, the token
             is rejected even if the signature is valid.
          4. Atomically claims the authorization (exactly-once semantics),
             binding the presented ``token_hash`` into the atomic UPDATE WHERE
             clause (EP-AUTH-009/010).
          5. Advances the transition to ``'executing'`` with a stage guard
             (``WHERE stage = 'authorized'``).  The claim and transition
             advancement occur in a single SAVEPOINT; if the advancement
             fails the claim is rolled back.
          6. Generates and persists an ``execution_attempt_id`` on the
             authorization record.
          7. Returns a dict with the claimed authorization + execution attempt ID.

        If any step fails (bad signature, payload mismatch, token-hash mismatch,
        already used, expired, not found, transition not in 'authorized'
        stage), returns ``None``.

        Args:
            conn:               Caller-supplied connection (already inside a
                                transaction).  Must not be ``None``.
            authorization_id:   The XID of the authorization to claim.
            signed_token:       The full signed token JSON string.
            payload_hash:       The payload hash the proxy observed.
            proxy_principal_id: XID of the proxy claiming the token.
            public_key:         The EP's :class:`VerifyKey`.

        Returns:
            A dict with the claimed authorization fields and
            ``execution_attempt_id``, or ``None`` if the claim failed.
        """
        # 1. Parse the signed token JSON.
        try:
            token_data = json.loads(signed_token)
        except (json.JSONDecodeError, TypeError):
            return None

        # 2. Verify the Ed25519 signature.
        signature_hex = token_data.get("signature", "")
        if not signature_hex:
            return None

        # Reconstruct the canonical payload (everything except signature).
        canonical_payload = {k: v for k, v in token_data.items() if k != "signature"}
        message = canonical_json_bytes(canonical_payload)
        try:
            public_key.verify(message, bytes.fromhex(signature_hex))
        except Exception:
            return None

        # 3. Verify the payload_hash matches what was authorized.
        stored_payload_hash = token_data.get("payload_hash", "")
        if payload_hash != stored_payload_hash:
            return None

        # 4. Verify authorization_id in the token matches the requested one.
        if token_data.get("authorization_id") != authorization_id:
            return None

        # 5. Compute SHA-256 of the presented signed_token and compare to the
        #    stored token_hash in the database.  This binds the presented token
        #    to the database record, preventing a validly-signed token from being
        #    used if the record has a different token_hash.
        presented_token_hash = hashlib.sha256(signed_token.encode("utf-8")).hexdigest()

        # 6. Generate the execution_attempt_id up front so it can be stored on
        #    the authorization record within the same transaction as the claim.
        execution_attempt_id = str(XID.new())

        # 7. Use the caller-supplied connection to atomically claim the
        #    authorization and advance the transition.  A SAVEPOINT
        #    (conn.begin_nested()) wraps the claim + transition advancement so
        #    a failed advancement rolls back only the claim, not the caller's
        #    entire transaction.
        auth_repo = AuthorizationRepository(conn)
        transition_repo = TransitionRepository(conn)

        stored_auth = auth_repo.get_authorization(authorization_id)
        if stored_auth is None:
            return None
        stored_token_hash = stored_auth.get("token_hash", "")
        if not stored_token_hash or presented_token_hash != stored_token_hash:
            return None

        savepoint = conn.begin_nested()
        try:
            claimed = auth_repo.claim_authorization(
                authorization_id,
                proxy_principal_id,
                token_hash=presented_token_hash,
            )
            if claimed is None:
                savepoint.rollback()
                return None

            # Persist the execution_attempt_id on the authorization record.
            auth_repo.update_execution_attempt_id(authorization_id, execution_attempt_id)

            # Advance the transition to 'executing', guarding that the current
            #    stage is 'authorized'.  If this fails, roll back the claim.
            transition_id = claimed.get("transition_id", "")
            if transition_id:
                ok = transition_repo.update_stage(
                    transition_id,
                    "executing",
                    expected_current_stage="authorized",
                )
                if not ok:
                    savepoint.rollback()
                    return None
            else:
                # No transition to advance — cannot safely proceed.
                savepoint.rollback()
                return None

            savepoint.commit()
        except Exception:
            savepoint.rollback()
            raise

        # 8. Build and return the result dict.
        result: dict[str, Any] = {
            "authorization_id": authorization_id,
            "transition_id": claimed.get("transition_id", ""),
            "execution_attempt_id": execution_attempt_id,
            "payload_hash": claimed.get("payload_hash", payload_hash),
            "policy_set_hash": claimed.get("policy_set_hash", ""),
            "proxy_principal_id": proxy_principal_id,
            "claimed": True,
        }
        return result

    # ------------------------------------------------------------------ #
    # Staleness detection
    # ------------------------------------------------------------------ #

    def check_stale_authorization(
        self,
        authorization_id: str,
        current_policy_set_hash: str,
    ) -> bool:
        """Check whether an authorization is stale.

        Compares the stored ``policy_set_hash`` against
        ``current_policy_set_hash``.  If they differ, the relevant
        governance has changed since the token was issued, and the
        authorization is stale.

        Args:
            authorization_id:       The XID of the authorization.
            current_policy_set_hash: The current effective policy-set hash.

        Returns:
            ``True`` if stale, ``False`` if still valid.
        """
        with self.engine.connect() as conn:
            auth_repo = AuthorizationRepository(conn)
            auth = auth_repo.get_authorization(authorization_id)
            if auth is None:
                return True  # not found → treat as stale / invalid

            stored_hash = auth.get("policy_set_hash")
            if stored_hash is None or stored_hash == "":
                return current_policy_set_hash != ""

            return stored_hash != current_policy_set_hash

    # ------------------------------------------------------------------ #
    # Standalone token verification
    # ------------------------------------------------------------------ #

    def verify_token(
        self,
        signed_token: str,
        public_key: VerifyKey,
    ) -> AuthorizationToken | None:
        """Verify a signed token without claiming it.

        Parses the JSON, checks the Ed25519 signature, verifies expiration,
        and returns a reconstructed :class:`AuthorizationToken` if valid.
        Returns ``None`` if the token is malformed, has a bad signature,
        or is expired.

        Args:
            signed_token:  The full signed token JSON string.
            public_key:    The EP's :class:`VerifyKey`.

        Returns:
            An :class:`AuthorizationToken` if valid, ``None`` otherwise.
        """
        # 1. Parse the JSON.
        try:
            token_data = json.loads(signed_token)
        except (json.JSONDecodeError, TypeError):
            return None

        # 2. Extract and verify the signature.
        signature_hex = token_data.get("signature", "")
        if not signature_hex:
            return None

        canonical_payload = {k: v for k, v in token_data.items() if k != "signature"}
        message = canonical_json_bytes(canonical_payload)
        try:
            public_key.verify(message, bytes.fromhex(signature_hex))
        except Exception:
            return None

        # 3. Check expiration.
        expires_at_str = token_data.get("expires_at", "")
        if not expires_at_str:
            return None
        try:
            # Parse ISO 8601 with microseconds + Z.
            expires_dt = datetime.strptime(expires_at_str, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                tzinfo=UTC
            )
        except ValueError:
            return None

        if datetime.now(UTC) > expires_dt:
            return None

        # 4. Reconstruct the AuthorizationToken.
        matched_policy_versions = token_data.get("matched_policy_versions", {})
        if isinstance(matched_policy_versions, str):
            try:
                matched_policy_versions = json.loads(matched_policy_versions)
            except (json.JSONDecodeError, TypeError):
                matched_policy_versions = {}

        try:
            token = AuthorizationToken(
                authorization_id=token_data["authorization_id"],
                transition_id=token_data["transition_id"],
                agent_id=token_data["agent_id"],
                project_id=token_data["project_id"],
                branch_id=token_data["branch_id"],
                proxy_audience=token_data["proxy_audience"],
                tool=token_data["tool"],
                payload_hash=token_data["payload_hash"],
                policy_set_hash=token_data["policy_set_hash"],
                matched_policy_versions=matched_policy_versions,
                issued_at=token_data["issued_at"],
                expires_at=token_data["expires_at"],
                nonce=token_data["nonce"],
                signature=signature_hex,
            )
        except KeyError:
            return None

        return token
