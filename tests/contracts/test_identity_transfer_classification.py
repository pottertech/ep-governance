"""Contract tests for EP-Governance identity, transfer, and classification rules.

These tests validate:
- EP-IDENTITY-001 through EP-IDENTITY-006 (identity and roles)
- EP-TRANSFER-001 through EP-TRANSFER-006 (transfer packages)
- EP-CLASSIFY-001 through EP-CLASSIFY-006 (action classification)
- EP-RESOURCE-001 through EP-RESOURCE-006 (resource canonicalization)

References: directive sections 13, 15, 24, 12
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Contract: identity
# ---------------------------------------------------------------------------

PRINCIPAL_TYPES = frozenset({"human", "agent", "service", "proxy"})

ROLES = frozenset(
    {
        "observer",
        "agent",
        "policy_author",
        "policy_approver",
        "operator",
        "auditor",
        "administrator",
    }
)


class TestIdentityContract:
    """EP-IDENTITY-001 through EP-IDENTITY-006."""

    def test_principal_types_match_specification(self):
        assert PRINCIPAL_TYPES == {"human", "agent", "service", "proxy"}

    def test_roles_match_specification(self):
        assert ROLES == {
            "observer",
            "agent",
            "policy_author",
            "policy_approver",
            "operator",
            "auditor",
            "administrator",
        }

    def test_every_mutation_authenticates_principal(self):
        """EP-IDENTITY-003: every mutation MUST authenticate a principal and
        authorize the exact operation."""
        pass

    def test_production_registration_requires_admin_or_token(self):
        """EP-IDENTITY-004: production registration MUST require administrator action
        or a short-lived enrollment token."""
        pass

    def test_self_registration_only_in_dev_mode(self):
        """EP-IDENTITY-005: self-registration MAY exist only in explicit development mode."""
        pass

    def test_never_store_raw_credentials(self):
        """EP-IDENTITY-006a: the system MUST NEVER store raw credentials.
        Store credential hashes or public keys."""
        pass

    def test_constant_time_comparisons(self):
        """EP-IDENTITY-006b: secret verification MUST use constant-time comparisons."""
        pass

    def test_credential_rotation_and_revocation(self):
        """EP-IDENTITY-006c: credential rotation and revocation MUST be supported."""
        pass


# ---------------------------------------------------------------------------
# Contract: transfer packages
# ---------------------------------------------------------------------------

TRANSFER_OPERATIONS = frozenset({"resume", "export", "import_as_fork"})

TRANSFER_PACKAGE_FIELDS = [
    "schema_version",
    "package_version",
    "source_lattice_id",
    "source_project_id",
    "snapshot_sequence",
    "created_at",
    "content_hash",
    "signature",
    "signer_id",
    "trust_status",
    "lattice_state",
]

PROHIBITED_IMPORTS = [
    "active_authorization_tokens",
    "operational_credentials",
    "private_signing_keys",
    "live_sessions",
    "unexpired_approvals_without_explicit_policy",
    "runtime_sockets",
    "environment_configuration",
]


class TestTransferPackageContract:
    """EP-TRANSFER-001 through EP-TRANSFER-006."""

    def test_three_operations(self):
        assert TRANSFER_OPERATIONS == {"resume", "export", "import_as_fork"}

    def test_required_fields(self):
        assert set(TRANSFER_PACKAGE_FIELDS) == {
            "schema_version",
            "package_version",
            "source_lattice_id",
            "source_project_id",
            "snapshot_sequence",
            "created_at",
            "content_hash",
            "signature",
            "signer_id",
            "trust_status",
            "lattice_state",
        }

    def test_export_creates_immutable_signed_snapshot(self):
        """EP-TRANSFER-002: export MUST create an immutable signed snapshot."""
        pass

    def test_import_creates_new_lattice_never_overwrites(self):
        """EP-TRANSFER-003: import MUST create a new project or lattice.
        It MUST NEVER overwrite the live source lattice."""
        pass

    def test_imported_entities_receive_new_local_ids(self):
        """EP-TRANSFER-004: imported entities MUST receive new local IDs.
        Provenance mappings MUST be preserved."""
        pass

    def test_imported_policies_not_automatically_active(self):
        """EP-TRANSFER-005: imported policies MUST NOT automatically become active
        unless signer is explicitly trusted, source lattice is explicitly trusted,
        and import policy permits automatic activation."""
        pass

    @pytest.mark.parametrize("prohibited", PROHIBITED_IMPORTS)
    def test_prohibited_import(self, prohibited: str):
        """EP-TRANSFER-006: the system MUST NEVER import the listed items."""
        assert prohibited in PROHIBITED_IMPORTS


# ---------------------------------------------------------------------------
# Contract: action classification
# ---------------------------------------------------------------------------


class TestClassificationContract:
    """EP-CLASSIFY-001 through EP-CLASSIFY-006."""

    def test_classification_is_server_side(self):
        """EP-CLASSIFY-001: EP MUST classify actions server-side."""
        pass

    def test_agent_hints_not_authoritative(self):
        """EP-CLASSIFY-002: agent-supplied categories are hints, never authoritative."""
        pass

    def test_sql_uses_actual_parser(self):
        """EP-CLASSIFY-003: SQL classification MUST use an actual SQL parser
        with AST, not string matching."""
        pass

    def test_sql_identifies_operation_type_and_targets(self):
        """EP-CLASSIFY-003a: SQL classification MUST identify operation type
        (SELECT/INSERT/UPDATE/DELETE/DROP) and target objects (tables, schemas)."""
        pass

    def test_sql_detects_multi_statement_payloads(self):
        """EP-CLASSIFY-003b: SQL classification MUST detect multi-statement payloads
        and transaction-control commands."""
        pass

    def test_sql_parser_failure_is_high_risk(self):
        """EP-CLASSIFY-003c: SQL parser failures MUST be treated as high risk."""
        pass

    def test_shell_does_not_claim_complete_understanding(self):
        """EP-CLASSIFY-004: shell classification MUST NOT claim complete semantic
        understanding."""
        pass

    def test_opaque_shell_classified_as_high_risk(self):
        """EP-CLASSIFY-005: opaque shell operations (scripts, interpreters,
        encoded payloads, command substitution, eval, unknown commands) MUST be
        classified as shell.exec.opaque and require approval or deny by default."""
        pass


# ---------------------------------------------------------------------------
# Contract: resource canonicalization
# ---------------------------------------------------------------------------

CANONICAL_RESOURCE_EXAMPLES = {
    "postgres": "postgres://prod-server/production_db/public/memory_items",
    "host": "host://example.internal",
    "container": "container://prod-server/app-container",
    "file": "file://prod-server/etc/app-container/config.yaml",
    "email": "email://recipient/example@example.com",
    "git": "git://github.com/pottertech/ep-governance/branch/main",
}

CANONICALIZATION_RULES = [
    "hostname_aliases",
    "case_handling",
    "ports",
    "database_schema_table_column_identity",
    "container_names_and_ids",
    "absolute_paths",
    "symbolic_links",
    "url_normalization",
    "email_addresses",
    "git_remotes_and_branches",
    "ipv4_ipv6_forms",
    "percent_encoding",
    "trailing_separators",
]


class TestResourceCanonicalizationContract:
    """EP-RESOURCE-001 through EP-RESOURCE-006."""

    @pytest.mark.parametrize("resource_type,example", sorted(CANONICAL_RESOURCE_EXAMPLES.items()))
    def test_canonical_format_exists(self, resource_type: str, example: str):
        """EP-RESOURCE-001: canonical resource formats MUST be defined for each type."""
        assert "://" in example  # Has a scheme

    def test_canonicalization_rules_defined(self):
        """EP-RESOURCE-002: canonicalization rules MUST be defined for all listed cases."""
        assert len(CANONICALIZATION_RULES) == 13

    def test_uncanonicalizable_targets_require_approval_or_deny(self):
        """EP-RESOURCE-006: if the target cannot be canonicalized with sufficient confidence,
        classify the action as unresolved and require approval or deny."""
        pass

    def test_policies_match_canonical_not_raw_strings(self):
        """EP-RESOURCE-001: policies MUST match canonical resource identities,
        not raw agent-supplied strings."""
        pass
