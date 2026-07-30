"""Deterministic policy evaluation engine for EP-Governance.

The :class:`PolicyEngine` evaluates a proposed action against the set of
active policies and produces a :class:`PolicyResolution` describing the
governing effect, matched policies, and any detected conflicts.

Design constraints:
  - No embeddings, no network, no filesystem access.
  - Evaluation errors fail closed (``require_approval``).
  - Resolution follows priority → effect-precedence ordering.
  - Overrides are only honoured when ALL override controls are satisfied.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any

from .errors import MissingPolicyContextError
from .policies import Policy, PolicyEffect, PolicyScope
from .resources import match_glob

__all__ = [
    "PolicyMatch",
    "PolicyResolution",
    "PolicyEngine",
]


# --------------------------------------------------------------------------- #
# Dataclasses
# --------------------------------------------------------------------------- #


@dataclass
class PolicyMatch:
    """A policy that matched a proposed action.

    Attributes:
        policy:            The matched :class:`Policy`.
        matched_actions:   Action patterns from the policy that matched.
        matched_resources: Resource patterns from the policy that matched.
    """

    policy: Policy
    matched_actions: list[str]
    matched_resources: list[str]


@dataclass
class PolicyResolution:
    """The result of evaluating a proposed action.

    Attributes:
        effect:           The governing effect (``deny``, ``require_approval``,
                          ``warn``, ``allow``).
        matched_policies: All policies that matched the action.
        conflict:         ``True`` if two matched policies had equal priority
                          but contradictory effects.
        warnings:         Human-readable warning messages.
    """

    effect: str
    matched_policies: list[PolicyMatch]
    conflict: bool
    warnings: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #


class PolicyEngine:
    """Deterministic policy evaluation engine.

    Instantiate with a list of :class:`Policy` objects and call
    :meth:`evaluate` to resolve a proposed action.
    """

    def __init__(self, policies: list[Policy]) -> None:
        self._policies: list[Policy] = list(policies)
        # Index policies by id for override lookups
        self._by_id: dict[str, Policy] = {p.id: p for p in self._policies}

    # ------------------------------------------------------------------ #
    # Public
    # ------------------------------------------------------------------ #

    def evaluate(
        self,
        action_type: str,
        canonical_resources: list[str],
        context: dict[str, Any] | None = None,
    ) -> PolicyResolution:
        """Evaluate a proposed action against all active policies.

        Args:
        -----
        action_type:         The action type string (e.g. ``"postgres.execute"``).
        canonical_resources: List of canonical resource URIs.
        context:             Optional context dict for condition evaluation.

        Returns:
        --------
        A :class:`PolicyResolution`.
        """
        context = context or {}
        warnings: list[str] = []

        try:
            matched = self._match_policies(action_type, canonical_resources, context)
        except Exception as exc:
            # Fail closed
            warnings.append(f"Evaluation error (fail-closed): {exc}")
            return PolicyResolution(
                effect=PolicyEffect.require_approval.value,
                matched_policies=[],
                conflict=False,
                warnings=warnings,
            )

        if not matched:
            # No policy matched — default to require_approval (fail closed)
            return PolicyResolution(
                effect=PolicyEffect.require_approval.value,
                matched_policies=[],
                conflict=False,
                warnings=["No matching policy — failing closed"],
            )

        # ------------------------------------------------------------------ #
        # Check for overrides before resolving
        # ------------------------------------------------------------------ #
        # If an allow policy is an exception to a deny policy AND satisfies
        # all override controls, the allow overrides the deny.
        overridden_deny_ids = self._compute_overrides(matched, warnings)

        # Filter out overridden deny policies from resolution
        effective_matched = [m for m in matched if m.policy.id not in overridden_deny_ids]
        if not effective_matched:
            # Everything was overridden — treat as allow
            return PolicyResolution(
                effect=PolicyEffect.allow.value,
                matched_policies=matched,
                conflict=False,
                warnings=warnings,
            )

        # ------------------------------------------------------------------ #
        # Resolve: EP-POLICY-008 — priority alone MUST NEVER override deny.
        # If any matched (non-overridden) policy has effect=deny, the result
        # is deny regardless of higher-priority allow policies that lack
        # exception_to override controls.
        # ------------------------------------------------------------------ #
        all_effects = [self._effect_str(m.policy.effect) for m in effective_matched]

        # Check if any deny is present among effective (non-overridden) matches
        has_deny = "deny" in all_effects

        if has_deny:
            # Deny always wins unless it was overridden (already handled above).
            # Priority alone does NOT override deny (EP-POLICY-008).
            # Check for contradictions at the SAME priority as the deny
            deny_policies = [
                m for m in effective_matched if self._effect_str(m.policy.effect) == "deny"
            ]
            non_deny_at_same_priority = [
                m
                for m in effective_matched
                if self._effect_str(m.policy.effect) != "deny"
                and m.policy.priority in {d.policy.priority for d in deny_policies}
            ]
            if non_deny_at_same_priority:
                # Contradiction at the same priority as the deny
                conflict = True
                warnings.append(
                    f"Policy conflict: deny at priority "
                    f"{deny_policies[0].policy.priority} with contradictory "
                    f"non-deny effects. Deny wins by precedence."
                )
            else:
                conflict = False
            best_effect = "deny"
        else:
            # No deny among effective matches — resolve by priority
            max_priority = max(m.policy.priority for m in effective_matched)
            top_matches = [m for m in effective_matched if m.policy.priority == max_priority]

            top_effects = [self._effect_str(m.policy.effect) for m in top_matches]
            top_effect_set = set(top_effects)

            if len(top_effect_set) > 1:
                # Contradiction at the same priority
                best_effect = "require_approval"
                conflict = True
                warnings.append(
                    f"Policy conflict at priority {max_priority}: "
                    f"contradictory effects {top_effect_set}. "
                    "Failing closed to require_approval."
                )
            else:
                best_effect = top_effects[0]
                conflict = False

        return PolicyResolution(
            effect=best_effect,
            matched_policies=matched,  # return ALL matches, not just top
            conflict=conflict,
            warnings=warnings,
        )

    # ------------------------------------------------------------------ #
    # Private
    # ------------------------------------------------------------------ #

    def _match_policies(
        self,
        action_type: str,
        canonical_resources: list[str],
        context: dict[str, Any],
    ) -> list[PolicyMatch]:
        """Find all active, in-force policies matching the action and resources.

        Scope enforcement (defense in depth): even if the caller supplies
        an already-filtered policy collection, the engine verifies that
        each policy's scope is applicable to the evaluation context:

        - global:  always applicable
        - project: only if context['project_id'] matches policy.project_id
        - branch:  only if context['branch_id'] matches policy.branch_id
        - agent:   only if context['agent_id'] matches policy.agent_scope
        """
        matches: list[PolicyMatch] = []

        for policy in self._policies:
            # Status must be active
            status_val = self._status_str(policy.status)
            if status_val != "active":
                continue

            # Must be in force
            if not policy.is_in_force():
                continue

            # Scope enforcement (fail closed). Scoped policies MUST NOT be
            # evaluated without their authoritative context.
            scope_val = self._scope_str(policy.scope)
            if scope_val == "project":
                ctx_project = context.get("project_id")
                if ctx_project is None:
                    raise MissingPolicyContextError("project_id is required for project-scoped policy evaluation")
                if policy.project_id != ctx_project:
                    continue
            elif scope_val == "branch":
                ctx_branch = context.get("branch_id")
                if ctx_branch is None:
                    raise MissingPolicyContextError("branch_id is required for branch-scoped policy evaluation")
                if policy.branch_id != ctx_branch:
                    continue
            elif scope_val == "agent":
                ctx_agent = context.get("agent_id")
                if ctx_agent is None:
                    raise MissingPolicyContextError("agent_id is required for agent-scoped policy evaluation")
                if policy.agent_scope != ctx_agent:
                    continue
            # global: always applicable

            # Action matching (glob)
            matched_actions: list[str] = []
            for pattern in policy.actions:
                if fnmatch.fnmatchcase(action_type, pattern):
                    matched_actions.append(pattern)
            if not matched_actions:
                continue

            # Resource matching (glob)
            # When canonical_resources is empty (e.g. "SELECT 1" with no
            # table targets), a wildcard "*" pattern should still match.
            matched_resources: list[str] = []
            for res_pattern in policy.resources:
                if not canonical_resources:
                    if res_pattern == "*":
                        matched_resources.append(res_pattern)
                        break
                else:
                    for canonical in canonical_resources:
                        if match_glob(res_pattern, canonical):
                            matched_resources.append(res_pattern)
                            break
            if not matched_resources:
                continue

            # Condition evaluation
            if not self._conditions_match(policy.conditions, context):
                continue

            matches.append(
                PolicyMatch(
                    policy=policy,
                    matched_actions=matched_actions,
                    matched_resources=matched_resources,
                )
            )

        return matches

    def _conditions_match(
        self,
        conditions: dict[str, Any],
        context: dict[str, Any],
    ) -> bool:
        """Evaluate policy conditions against the context dict.

        Implements simple equality matching: for each key in *conditions*,
        the same key must exist in *context* with an equal value.
        If *conditions* is empty, the policy always matches.
        If a condition key is missing from *context*, the policy does NOT match.
        """
        if not conditions:
            return True
        for key, expected in conditions.items():
            if key not in context:
                return False
            if context[key] != expected:
                return False
        return True

    def _compute_overrides(
        self,
        matched: list[PolicyMatch],
        warnings: list[str],
    ) -> set[str]:
        """Determine which deny policies are overridden by allow exceptions.

        An allow policy overrides a deny policy if ALL of the following hold:
          1. The allow policy's ``exception_to`` lists the deny policy's id.
          2. The allow policy is narrower in scope than the deny
             (deny is global, allow is agent-scoped).
          3. The allow policy has ``valid_until`` set (time-bounded).
          4. The allow policy has ``justification`` set.
          5. The allow policy was ``approved_by`` a human.

        Returns the set of deny policy ids that are overridden.
        """
        overridden: set[str] = set()

        # Collect deny and allow matches
        deny_matches = [m for m in matched if self._effect_str(m.policy.effect) == "deny"]
        allow_matches = [m for m in matched if self._effect_str(m.policy.effect) == "allow"]

        if not deny_matches or not allow_matches:
            return overridden

        deny_by_id = {m.policy.id: m.policy for m in deny_matches}

        for allow_match in allow_matches:
            allow_policy = allow_match.policy
            exception_ids = allow_policy.exception_to or []

            for deny_id in exception_ids:
                deny_policy = deny_by_id.get(deny_id)
                if deny_policy is None:
                    # Referenced deny policy may not be in the matched set.
                    # Check the global index.
                    deny_policy = self._by_id.get(deny_id)
                if deny_policy is None:
                    # Referenced deny doesn't exist — can't override
                    warnings.append(
                        f"Allow policy {allow_policy.id} lists exception_to "
                        f"{deny_id} but no such deny policy found."
                    )
                    continue

                # Control 2: narrower scope
                allow_scope = self._scope_str(allow_policy.scope)
                deny_scope = self._scope_str(deny_policy.scope)
                if not (allow_scope == "agent" and deny_scope == "global"):
                    warnings.append(
                        f"Override attempt by {allow_policy.id}: allow policy "
                        f"must be agent-scoped and deny must be global-scoped."
                    )
                    continue

                # Control 3: valid_until set
                if not allow_policy.valid_until:
                    warnings.append(
                        f"Override attempt by {allow_policy.id}: valid_until must be set."
                    )
                    continue

                # Control 4: justification set
                if not allow_policy.justification:
                    warnings.append(
                        f"Override attempt by {allow_policy.id}: justification must be set."
                    )
                    continue

                # Control 5: approved_by a human
                # (We check that approved_by is non-null; human-ness is
                # enforced at approval time by the identity layer.)
                if not allow_policy.approved_by:
                    warnings.append(
                        f"Override attempt by {allow_policy.id}: "
                        "approved_by must be set (by a human)."
                    )
                    continue

                # All controls satisfied — override the deny
                overridden.add(deny_id)
                warnings.append(
                    f"Override granted: allow policy {allow_policy.id} "
                    f"overrides deny policy {deny_id}."
                )

        return overridden

    # ------------------------------------------------------------------ #
    # Helpers for enum/str coercion
    # ------------------------------------------------------------------ #

    @staticmethod
    def _effect_str(effect: Any) -> str:
        """Return the string value of an effect (enum or str)."""
        if isinstance(effect, PolicyEffect):
            return effect.value
        return str(effect)

    @staticmethod
    def _status_str(status: Any) -> str:
        """Return the string value of a status."""
        from .policies import PolicyStatus

        if isinstance(status, PolicyStatus):
            return status.value
        return str(status)

    @staticmethod
    def _scope_str(scope: Any) -> str:
        """Return the string value of a scope."""
        if isinstance(scope, PolicyScope):
            return scope.value
        return str(scope)
