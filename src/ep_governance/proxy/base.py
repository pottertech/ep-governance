"""EP-Governance governed proxy base class.

All proxies inherit from this base. A proxy:
1. Authenticates to EP
2. Verizes authorization signature
3. Verifies token audience
4. Verifies expiration
5. Verifies payload hash
6. Atomically claims authorization
7. Executes through a bounded adapter
8. Captures structured results
9. Submits authenticated result to EP
10. Never directly writes audit events
11. Redacts secrets
12. Enforces output-size limits
13. Enforces execution timeouts
14. Prevents uncontrolled environment inheritance
"""

from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.engine import Connection
from sqlalchemy.exc import OperationalError

from ..authorizations import AuthorizationEngine, AuthorizationToken
from ..branches import BranchCommitter
from ..canonical import canonical_hash
from ..classification import get_classifier
from ..db.transactions import serializable_transaction
from ..errors import EPError, IllegalTransitionError
from ..policy_engine import PolicyEngine
from ..transitions import TransitionEngine
from ..xid import XID

__all__ = [
    "ExecutionResult",
    "ProxyConfig",
    "GovernedProxy",
    "PROXY_TIMEOUT_SECONDS",
    "PROXY_MAX_OUTPUT_BYTES",
]

PROXY_TIMEOUT_SECONDS = 30
PROXY_MAX_OUTPUT_BYTES = 1024 * 1024  # 1 MB


@dataclass
class ProxyConfig:
    """Configuration for a governed proxy."""

    target_connection_string: str
    proxy_audience: str
    ep_service_principal_id: str
    timeout_seconds: int = PROXY_TIMEOUT_SECONDS
    max_output_bytes: int = PROXY_MAX_OUTPUT_BYTES


@dataclass
class ExecutionResult:
    """Result of a proxy execution attempt."""

    success: bool
    exit_status: str  # "success", "failure", "timeout", "uncertain"
    result_summary: str
    rows_affected: int = 0
    output: Any = None
    execution_attempt_id: str = ""
    started_at: str = ""
    completed_at: str = ""
    redacted: bool = False


class GovernedProxy(ABC):
    """Base class for all governed proxies.

    A proxy runs as a distinct process with credentials unavailable to agents.
    It verifies authorization tokens, checks payload hashes, atomically claims
    authorizations, executes through a bounded adapter, and submits results to EP.
    """

    def __init__(
        self,
        conn: Connection,
        auth_engine: AuthorizationEngine,
        config: ProxyConfig,
        transition_engine: TransitionEngine | None = None,
        branch_committer: BranchCommitter | None = None,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        self.conn = conn
        self.auth_engine = auth_engine
        self.config = config
        self.transition_engine = transition_engine
        self.branch_committer = branch_committer
        self.policy_engine = policy_engine

    def execute(
        self,
        signed_token: str,
        payload: dict[str, Any],
        public_key: Any,
    ) -> ExecutionResult:
        """Execute a governed action.

        This is the main entry point. The proxy:
        1. Verifies the token signature
        2. Computes the payload hash from the actual payload (NOT caller-supplied)
        3. Verifies the computed hash matches the authorized payload hash
        4. Verifies proxy audience
        5. Checks for stale authorization (policy set changes)
        6. Atomically claims the authorization
        7. Executes the action through the bounded adapter
        8. Returns the result

        Args:
            signed_token: The signed authorization token JSON string.
            payload: The actual payload to execute. The proxy computes the hash.
            public_key: The Ed25519 public key for signature verification.

        Returns:
            ExecutionResult with success/failure/timeout status.
        """
        attempt_id = str(XID.new())
        started_at = self._now_iso()

        # Step 1: Verify token signature
        token = self.auth_engine.verify_token(signed_token, public_key)
        if token is None:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="Token verification failed: invalid signature or expired",
                execution_attempt_id=attempt_id,
                started_at=started_at,
                completed_at=self._now_iso(),
            )

        # Step 2: Compute payload hash from the ACTUAL payload (Critical fix 1)
        # The caller MUST NOT supply the hash — the proxy derives it.
        actual_payload_hash = "sha256:" + canonical_hash(payload)

        # Step 3: Verify computed hash matches the authorized payload hash
        if token.payload_hash != actual_payload_hash:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="Payload hash mismatch: actual payload does not match authorized payload",
                execution_attempt_id=attempt_id,
                started_at=started_at,
                completed_at=self._now_iso(),
            )

        # Step 4: Verify proxy audience
        if token.proxy_audience != self.config.proxy_audience:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=f"Token audience mismatch: expected {self.config.proxy_audience}, got {token.proxy_audience}",
                execution_attempt_id=attempt_id,
                started_at=started_at,
                completed_at=self._now_iso(),
            )

        # Step 5+6: Policy revalidation AND atomic claim in a single
        # SERIALIZABLE transaction (Critical fix 2 — TOCTOU race).
        #
        # The previous implementation evaluated policies and then claimed the
        # authorization in two separate operations.  A policy could change
        # between evaluation and claim, allowing an action to proceed under a
        # stale policy set.  We now wrap both operations in a single
        # serializable transaction so no policy can change between evaluation
        # and claim.  If the serializable transaction fails due to a
        # serialization conflict (concurrent policy modification), we return a
        # "stale authorization" error so the caller can re-propose.
        #
        # Issue 5 (High 6 — prepare before claim): we also validate the
        # adapter-specific payload constraints BEFORE claiming the token.  If
        # validation fails, the token is not consumed.
        #
        # Issue High 6: serializable_transaction() requires a clean connection.
        # The reads above (token verification, authorization lookup) may have
        # autobegun a transaction. Commit those read-only operations to clean
        # the connection. This is safe because the reads are non-mutating.
        if self.conn.in_transaction():
            self.conn.commit()
        try:
            with serializable_transaction(self.conn):
                # --- Step 5: Policy revalidation ----------------------------
                if self.policy_engine is not None:
                    # 5a. Classify the payload using the same classifier used
                    #     at proposal.
                    classifier = get_classifier(token.tool)
                    if classifier is None:
                        return ExecutionResult(
                            success=False,
                            exit_status="failure",
                            result_summary=f"No classifier available for tool '{token.tool}'",
                            execution_attempt_id=attempt_id,
                            started_at=started_at,
                            completed_at=self._now_iso(),
                        )

                    try:
                        classification = classifier.classify(token.tool, payload)
                    except Exception as exc:
                        return ExecutionResult(
                            success=False,
                            exit_status="failure",
                            result_summary=f"Classification failed: {exc!s}",
                            execution_attempt_id=attempt_id,
                            started_at=started_at,
                            completed_at=self._now_iso(),
                        )

                    action_type = classification.action_type
                    canonical_resources = classification.canonical_resources

                    # 5b. Evaluate current active policies with agent/project/branch context.
                    context = {
                        "agent_id": token.agent_id,
                        "project_id": token.project_id,
                        "branch_id": token.branch_id,
                    }
                    resolution = self.policy_engine.evaluate(
                        action_type=action_type,
                        canonical_resources=canonical_resources,
                        context=context,
                    )

                    # 5c. If the current policy resolution denies or requires
                    #     approval, reject the action even if the hash matches.
                    if resolution.effect in ("deny", "require_approval"):
                        return ExecutionResult(
                            success=False,
                            exit_status="failure",
                            result_summary=(
                                f"Action blocked by current policy: effect='{resolution.effect}'"
                            ),
                            execution_attempt_id=attempt_id,
                            started_at=started_at,
                            completed_at=self._now_iso(),
                        )

                    # 5d. Compute a fresh policy_set_hash from the matched
                    #     policies.  Build {policy_id: version} for each matched
                    #     policy, sort by id, and compute canonical_hash —
                    #     matching the issuance-time computation.
                    fresh_policy_versions: dict[str, int] = {}
                    for match in resolution.matched_policies:
                        p = match.policy
                        version = p.activation_version if p.activation_version is not None else 0
                        fresh_policy_versions[p.id] = int(version)

                    if fresh_policy_versions:
                        sorted_pairs = sorted(fresh_policy_versions.items())
                        fresh_policy_set_hash = canonical_hash(sorted_pairs)
                    else:
                        fresh_policy_set_hash = ""

                    # 5e. Compare the fresh hash to the token's policy_set_hash.
                    if fresh_policy_set_hash != token.policy_set_hash:
                        return ExecutionResult(
                            success=False,
                            exit_status="failure",
                            result_summary="Stale authorization: effective policy set has changed",
                            execution_attempt_id=attempt_id,
                            started_at=started_at,
                            completed_at=self._now_iso(),
                        )

                # --- Step 5.5: Validate adapter payload before claim --------
                # (High fix 6 — prepare before claim)
                # Adapter-specific validation runs BEFORE the token is claimed
                # so that a malformed payload does not consume the authorization.
                validation_error = self._validate_adapter_payload(payload, token)
                if validation_error is not None:
                    return ExecutionResult(
                        success=False,
                        exit_status="failure",
                        result_summary=validation_error,
                        execution_attempt_id=attempt_id,
                        started_at=started_at,
                        completed_at=self._now_iso(),
                    )

                # --- Step 6: Atomically claim the authorization -------------
                # The claim must also verify the signed-token hash matches the
                # stored hash (High fix 6).
                claimed = self.auth_engine.verify_and_claim(
                    authorization_id=token.authorization_id,
                    signed_token=signed_token,
                    payload_hash=actual_payload_hash,
                    proxy_principal_id=self.config.ep_service_principal_id,
                    public_key=public_key,
                )
        except OperationalError:
            # Serialization conflict — a concurrent transaction modified
            # policies or the authorization record between our evaluation and
            # claim.  Return a stale-authorization error so the caller can
            # re-propose.
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="Stale authorization: serialization conflict during policy revalidation",
                execution_attempt_id=attempt_id,
                started_at=started_at,
                completed_at=self._now_iso(),
            )

        if claimed is None:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="Authorization claim failed: token already used, expired, or not found",
                execution_attempt_id=attempt_id,
                started_at=started_at,
                completed_at=self._now_iso(),
            )

        # Step 7: Execute with timeout
        try:
            result = self._execute_with_timeout(payload, token, attempt_id)
            result.execution_attempt_id = attempt_id
            result.started_at = started_at
            result.completed_at = self._now_iso()
        except TimeoutError:
            result = ExecutionResult(
                success=False,
                exit_status="uncertain",
                result_summary="Execution timed out — outcome uncertain",
                execution_attempt_id=attempt_id,
                started_at=started_at,
                completed_at=self._now_iso(),
            )
        except Exception:
            # High fix 12: do not expose internal error details
            result = ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=f"Execution error (reference: {attempt_id})",
                execution_attempt_id=attempt_id,
                started_at=started_at,
                completed_at=self._now_iso(),
            )

        # Step 8: Record the result and, on success, commit the branch head.
        #
        # Transactional-safety invariant: the governance graph must reflect
        # actual realised state.  Therefore:
        #   - On adapter FAILURE or TIMEOUT: call record_result() to advance
        #     the transition to 'failed' / 'execution_uncertain'.  No node is
        #     created and the branch head is unchanged.
        #   - On adapter SUCCESS: call branch_committer.commit() which
        #     atomically records the success result, creates the graph node,
        #     advances the branch head, AND advances the transition stage to
        #     'succeeded' — all in a single database transaction.  We do NOT
        #     call record_result(success) separately before commit(); that was
        #     the old unsafe flow which left the transition 'succeeded' with
        #     no node if commit() failed.
        #   - If commit() fails for any reason (stale head, concurrent
        #     commit, DB error), the entire transaction rolls back and the
        #     transition remains at 'executing'.  We then mark it
        #     'execution_uncertain' via record_result(timeout) so an operator
        #     can reconcile manually, and return exit_status='uncertain'.
        #   - Exceptions are NEVER silently swallowed.
        if self.transition_engine is not None:
            if result.exit_status == "success":
                # Success path: single atomic commit transaction.
                # Enforced mode requires a branch committer — there is no
                # fallback that would record success without creating a node.
                if self.branch_committer is None:
                    raise EPError("Branch committer is required for enforced mode execution")
                try:
                    transition = self.transition_engine.get_transition(
                        token.transition_id,
                    )
                    if transition is None:
                        raise IllegalTransitionError(f"Transition {token.transition_id} not found")
                    branch_id: str = transition.get("branch_id", "")
                    agent_id: str = transition.get("agent_id", "")
                    expected_head_id: str | None = transition.get(
                        "expected_head_id",
                    )
                    expected_version_raw = transition.get("expected_version")

                    from ..db.repositories import BranchRepository

                    branch_repo = BranchRepository(self.conn)
                    current_head, current_version = branch_repo.get_head(
                        branch_id,
                    )
                    commit_expected_head = (
                        expected_head_id if expected_head_id is not None else current_head
                    )
                    commit_expected_version = (
                        int(expected_version_raw)
                        if expected_version_raw is not None
                        else current_version
                    )
                    branch = branch_repo.get_branch(branch_id)
                    lattice_id = (
                        branch.get("lattice_id", branch_id) if branch is not None else branch_id
                    )

                    self.branch_committer.commit(
                        transition_id=token.transition_id,
                        branch_id=branch_id,
                        agent_id=agent_id,
                        description=result.result_summary,
                        bt_planning_budget=0.0,
                        metadata={},
                        expected_head_id=commit_expected_head,
                        expected_version=commit_expected_version,
                        lattice_id=lattice_id,
                    )
                except Exception:
                    # Commit failed — the action already happened but the
                    # governance graph does not reflect it.  Roll back the
                    # failed branch transaction first so the connection is in
                    # a clean state, then mark the transition as
                    # execution_uncertain so an operator can reconcile manually.
                    self.conn.rollback()
                    try:
                        self.transition_engine.record_result(
                            transition_id=token.transition_id,
                            exit_status="timeout",
                            result_summary=(
                                "Governance commitment failed — "
                                "manual reconciliation required "
                                f"(reference: {attempt_id})"
                            ),
                        )
                    except Exception:
                        # If even the uncertain-state recording fails, we
                        # must NOT silently suppress it — log a critical
                        # error to stderr so operators can investigate.
                        print(
                            f"[EP-Governance CRITICAL] Failed to record "
                            f"execution_uncertain after governance commit "
                            f"failure: transition_id={token.transition_id} "
                            f"attempt_id={attempt_id}",
                            file=sys.stderr,
                        )
                    return ExecutionResult(
                        success=False,
                        exit_status="uncertain",
                        result_summary=(
                            "Execution succeeded but governance commit "
                            f"failed — manual reconciliation required "
                            f"(reference: {attempt_id})"
                        ),
                        execution_attempt_id=attempt_id,
                        started_at=started_at,
                        completed_at=self._now_iso(),
                    )
            elif result.exit_status == "failure":
                # Failure path: record the failure, no node created.
                self.transition_engine.record_result(
                    transition_id=token.transition_id,
                    exit_status="failure",
                    result_summary=result.result_summary,
                )
            else:
                # Timeout / uncertain path: record as execution_uncertain.
                self.transition_engine.record_result(
                    transition_id=token.transition_id,
                    exit_status="timeout",
                    result_summary=result.result_summary,
                )

        return result

    def _execute_with_timeout(
        self,
        payload: dict[str, Any],
        token: AuthorizationToken,
        attempt_id: str,
    ) -> ExecutionResult:
        """Execute the bounded adapter with a timeout."""
        # For now, execute directly. In production, use a subprocess or
        # async with timeout. The timeout is enforced by the adapter.
        return self._execute_adapter(payload, token, attempt_id)

    @abstractmethod
    def _execute_adapter(
        self,
        payload: dict[str, Any],
        token: AuthorizationToken,
        attempt_id: str,
    ) -> ExecutionResult:
        """Execute the action through the bounded adapter.

        Subclasses implement this with the specific tool (SQL, shell, etc.).
        """
        ...

    def _validate_adapter_payload(
        self,
        payload: dict[str, Any],
        token: AuthorizationToken,
    ) -> str | None:
        """Validate adapter-specific payload constraints WITHOUT side effects.

        This method is called BEFORE the authorization token is claimed (High
        fix 6 — prepare before claim).  If validation fails, the token is NOT
        consumed and the caller receives a failure result.

        The base implementation returns ``None`` (valid).  Subclasses override
        this to check adapter-specific constraints such as forbidden
        operations, opaque classification, or missing required fields.

        Args:
            payload: The actual payload dict to validate.
            token:   The verified authorization token.

        Returns:
            ``None`` if the payload is valid, or an error message string
            describing why validation failed.
        """
        return None

    def _now_iso(self) -> str:
        return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"

    def _redact(self, output: str) -> str:
        """Redact secrets from output before returning."""
        # Basic redaction: mask password-like patterns
        import re

        redacted = re.sub(
            r"(password|passwd|pwd|secret|token|key)[=:]\s*\S+",
            r"\1=***REDACTED***",
            output,
            flags=re.IGNORECASE,
        )
        return redacted

    def _enforce_output_limit(self, output: str) -> str:
        """Truncate output to max_output_bytes."""
        if len(output.encode("utf-8")) > self.config.max_output_bytes:
            return output[: self.config.max_output_bytes] + "\n... [TRUNCATED]"
        return output
