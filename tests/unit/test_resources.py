"""Unit tests for EP-Governance resource canonicalization.

References normative rules:
  EP-RESOURCE-001: canonical resource formats for postgres, host, container, file, email, git
  EP-RESOURCE-002: hostname lowercase normalization, default ports
  EP-RESOURCE-003: postgres database canonicalization
  EP-RESOURCE-004: file path normalization (trailing slashes, symlink rejection)
  EP-RESOURCE-005: email address lowercase normalization, git remote canonicalization
  EP-RESOURCE-006: uncanonicalizable resources raise error
"""

from __future__ import annotations

import pytest

from ep_governance.errors import ResourceCanonicalizationError
from ep_governance.resources import (
    CanonicalResource,
    canonicalize_resource,
    match_glob,
)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
def valid_xid() -> str:
    """A valid 20-char base32hex XID string for use in policy fields."""
    return "0123456789abcdefgh"


# --------------------------------------------------------------------------- #
# EP-RESOURCE-001: Each scheme is canonicalized
# --------------------------------------------------------------------------- #


class TestCanonicalizePostgres:
    """Tests for postgres:// canonicalization (EP-RESOURCE-003)."""

    def test_postgres_basic(self):
        """postgres:// URI with host, db, schema, table canonicalizes correctly."""
        result = canonicalize_resource("postgres://cloudhub/gbrain_pilot/public/memory_items")
        assert result.scheme == "postgres"
        assert result.canonical == "postgres://cloudhub/gbrain_pilot/public/memory_items"
        assert result.raw == "postgres://cloudhub/gbrain_pilot/public/memory_items"

    def test_postgres_lowercase_identifiers(self):
        """Postgres identifiers are lowercased."""
        result = canonicalize_resource("postgres://cloudhub/Gbrain_Pilot/Public/Memory_Items")
        assert result.canonical == "postgres://cloudhub/gbrain_pilot/public/memory_items"

    def test_postgres_postgresql_alias(self):
        """postgresql:// scheme is normalized to postgres://."""
        result = canonicalize_resource("postgresql://cloudhub/gbrain_pilot/public/memory_items")
        assert result.scheme == "postgres"
        assert result.canonical.startswith("postgres://")

    def test_postgres_missing_database_raises(self):
        """postgres URI without a database path segment raises."""
        with pytest.raises(ResourceCanonicalizationError):
            canonicalize_resource("postgres://cloudhub")

    def test_postgres_too_many_segments_raises(self):
        """postgres URI with more than 3 path segments raises."""
        with pytest.raises(ResourceCanonicalizationError):
            canonicalize_resource("postgres://cloudhub/db/schema/table/extra")


class TestCanonicalizeHost:
    """Tests for host:// canonicalization (EP-RESOURCE-002)."""

    def test_host_basic(self):
        result = canonicalize_resource("host://cloudhub.pottersquill.com")
        assert result.scheme == "host"
        assert result.canonical == "host://cloudhub.pottersquill.com"
        assert result.path == ""

    def test_host_with_port(self):
        result = canonicalize_resource("host://cloudhub.pottersquill.com:8080")
        assert result.canonical == "host://cloudhub.pottersquill.com:8080"

    def test_host_rejects_path(self):
        """host:// URI must not have a path."""
        with pytest.raises(ResourceCanonicalizationError):
            canonicalize_resource("host://cloudhub.pottersquill.com/some/path")


class TestCanonicalizeContainer:
    """Tests for container:// canonicalization (EP-RESOURCE-001)."""

    def test_container_basic(self):
        result = canonicalize_resource("container://cloudhub/open-webui")
        assert result.scheme == "container"
        assert result.canonical == "container://cloudhub/open-webui"
        assert result.path == "/open-webui"

    def test_container_name_lowercased(self):
        result = canonicalize_resource("container://cloudhub/Open-WebUI")
        assert result.canonical == "container://cloudhub/open-webui"

    def test_container_requires_exactly_one_segment(self):
        with pytest.raises(ResourceCanonicalizationError):
            canonicalize_resource("container://cloudhub")
        with pytest.raises(ResourceCanonicalizationError):
            canonicalize_resource("container://cloudhub/one/two")

    def test_container_invalid_name_raises(self):
        with pytest.raises(ResourceCanonicalizationError):
            canonicalize_resource("container://cloudhub/!invalid")


class TestCanonicalizeFile:
    """Tests for file:// canonicalization (EP-RESOURCE-004)."""

    def test_file_basic(self):
        result = canonicalize_resource("file://cloudhub/etc/open-webui/config.yaml")
        assert result.scheme == "file"
        assert "etc/open-webui/config.yaml" in result.canonical

    def test_file_empty_host_defaults_localhost(self):
        result = canonicalize_resource("file:///etc/open-webui/config.yaml")
        assert result.canonical.startswith("file://localhost/")

    def test_file_rejects_symlink_traversal(self):
        """file paths with .. segments are rejected (EP-RESOURCE-004)."""
        with pytest.raises(ResourceCanonicalizationError):
            canonicalize_resource("file://cloudhub/etc/../etc/passwd")

    def test_file_rejects_root(self):
        with pytest.raises(ResourceCanonicalizationError):
            canonicalize_resource("file://cloudhub/")


class TestCanonicalizeEmail:
    """Tests for email:// canonicalization (EP-RESOURCE-005)."""

    def test_email_basic(self):
        result = canonicalize_resource("email://recipient/example@example.com")
        assert result.scheme == "email"
        assert result.canonical == "email://recipient/example@example.com"

    def test_email_lowercase_normalization(self):
        """Email address is lowercased (EP-RESOURCE-005)."""
        result = canonicalize_resource("email://recipient/Example@Example.COM")
        assert result.canonical == "email://recipient/example@example.com"

    def test_email_missing_type_raises(self):
        with pytest.raises(ResourceCanonicalizationError):
            canonicalize_resource("email://example@example.com")

    def test_email_invalid_address_raises(self):
        with pytest.raises(ResourceCanonicalizationError):
            canonicalize_resource("email://recipient/not-an-email")

    def test_email_type_lowercased(self):
        result = canonicalize_resource("email://Recipient/example@example.com")
        assert result.canonical == "email://recipient/example@example.com"


class TestCanonicalizeGit:
    """Tests for git:// canonicalization (EP-RESOURCE-005)."""

    def test_git_basic(self):
        result = canonicalize_resource("git://github.com/pottertech/ep-governance/branch/main")
        assert result.scheme == "git"
        assert result.canonical == "git://github.com/pottertech/ep-governance/branch/main"

    def test_git_missing_branch_segment_raises(self):
        with pytest.raises(ResourceCanonicalizationError):
            canonicalize_resource("git://github.com/pottertech/ep-governance")

    def test_git_too_short_raises(self):
        with pytest.raises(ResourceCanonicalizationError):
            canonicalize_resource("git://github.com/pottertech")


# --------------------------------------------------------------------------- #
# EP-RESOURCE-002: Hostname case normalization and port handling
# --------------------------------------------------------------------------- #


class TestHostnameNormalization:
    """Tests for hostname case normalization (EP-RESOURCE-002)."""

    def test_uppercase_hostname_lowercased(self):
        """Uppercase hostname is normalized to lowercase."""
        result = canonicalize_resource("host://CLOUDHUB.POTTERSQUILL.COM")
        assert result.canonical == "host://cloudhub.pottersquill.com"

    def test_mixed_case_hostname_lowercased(self):
        result = canonicalize_resource("host://CloudHub.PottersQuill.com")
        assert result.canonical == "host://cloudhub.pottersquill.com"

    def test_postgres_uppercase_host_lowercased(self):
        result = canonicalize_resource("postgres://CLOUDHUB/db/schema/table")
        assert result.canonical == "postgres://cloudhub/db/schema/table"

    def test_container_uppercase_host_lowercased(self):
        result = canonicalize_resource("container://CLOUDHUB/open-webui")
        assert result.canonical == "container://cloudhub/open-webui"

    def test_ip_address_normalized(self):
        """IPv4 addresses are preserved in canonical form."""
        result = canonicalize_resource("host://192.168.1.1")
        assert result.canonical == "host://192.168.1.1"


# --------------------------------------------------------------------------- #
# Port handling
# --------------------------------------------------------------------------- #


class TestPortHandling:
    """Tests for port normalization (EP-RESOURCE-002)."""

    def test_postgres_default_port_omitted(self):
        """When postgres uses default port 5432, it's omitted from canonical URI."""
        result = canonicalize_resource("postgres://cloudhub:5432/db/schema/table")
        assert ":5432" not in result.canonical
        assert result.canonical == "postgres://cloudhub/db/schema/table"

    def test_postgres_non_default_port_included(self):
        result = canonicalize_resource("postgres://cloudhub:5433/db/schema/table")
        assert ":5433" in result.canonical

    def test_host_explicit_port_included(self):
        result = canonicalize_resource("host://cloudhub.pottersquill.com:8080")
        assert ":8080" in result.canonical


# --------------------------------------------------------------------------- #
# EP-RESOURCE-004: Path normalization (trailing slashes removed)
# --------------------------------------------------------------------------- #


class TestPathNormalization:
    """Tests for path normalization (EP-RESOURCE-004)."""

    def test_postgres_trailing_slash_removed(self):
        result = canonicalize_resource("postgres://cloudhub/db/schema/table/")
        assert not result.canonical.endswith("/")

    def test_file_trailing_slash_removed(self):
        result = canonicalize_resource("file://cloudhub/etc/open-webui/")
        assert not result.path.endswith("/")

    def test_file_duplicate_slashes_collapsed(self):
        result = canonicalize_resource("file://cloudhub/etc//open-webui/config.yaml")
        assert "//" not in result.path


# --------------------------------------------------------------------------- #
# match_glob tests
# --------------------------------------------------------------------------- #


class TestMatchGlob:
    """Tests for match_glob with glob patterns."""

    def test_exact_match(self):
        assert (
            match_glob(
                "postgres://cloudhub/gbrain_pilot/public/memory_items",
                "postgres://cloudhub/gbrain_pilot/public/memory_items",
            )
            is True
        )

    def test_single_wildcard(self):
        assert (
            match_glob(
                "postgres://cloudhub/*",
                "postgres://cloudhub/gbrain_pilot/public/memory_items",
            )
            is True
        )

    def test_double_wildcard_matches_multiple_segments(self):
        """** wildcards match across path segments."""
        assert (
            match_glob(
                "postgres://cloudhub/**",
                "postgres://cloudhub/gbrain_pilot/public/memory_items",
            )
            is True
        )

    def test_double_wildcard_in_middle(self):
        assert (
            match_glob(
                "postgres://**/memory_items",
                "postgres://cloudhub/gbrain_pilot/public/memory_items",
            )
            is True
        )

    def test_no_match(self):
        assert (
            match_glob(
                "postgres://otherhost/*",
                "postgres://cloudhub/gbrain_pilot/public/memory_items",
            )
            is False
        )

    def test_empty_pattern_returns_false(self):
        assert match_glob("", "postgres://cloudhub/db") is False

    def test_empty_canonical_returns_false(self):
        assert match_glob("postgres://*", "") is False


# --------------------------------------------------------------------------- #
# EP-RESOURCE-006: Uncanonicalizable resources raise error
# --------------------------------------------------------------------------- #


class TestUncanonicalizableResources:
    """Tests for resources that cannot be canonicalized (EP-RESOURCE-006)."""

    def test_empty_string_raises(self):
        with pytest.raises(ResourceCanonicalizationError):
            canonicalize_resource("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ResourceCanonicalizationError):
            canonicalize_resource("   ")

    def test_no_scheme_raises(self):
        with pytest.raises(ResourceCanonicalizationError):
            canonicalize_resource("cloudhub/db/schema/table")

    def test_unsupported_scheme_raises(self):
        with pytest.raises(ResourceCanonicalizationError):
            canonicalize_resource("ftp://cloudhub/file")

    def test_invalid_hostname_label_raises(self):
        with pytest.raises(ResourceCanonicalizationError):
            canonicalize_resource("host://-invalid")

    def test_scheme_hint_unsupported_raises(self):
        with pytest.raises(ResourceCanonicalizationError):
            canonicalize_resource("cloudhub", scheme_hint="ftp")

    def test_scheme_hint_applied(self):
        """A valid scheme hint is applied when raw has no scheme."""
        result = canonicalize_resource("cloudhub/db/schema/table", scheme_hint="postgres")
        assert result.scheme == "postgres"


# --------------------------------------------------------------------------- #
# CanonicalResource dataclass properties
# --------------------------------------------------------------------------- #


class TestCanonicalResource:
    """Tests for the CanonicalResource dataclass."""

    def test_frozen_dataclass(self):
        """CanonicalResource is immutable."""
        result = canonicalize_resource("host://cloudhub.pottersquill.com")
        with pytest.raises(AttributeError):
            result.scheme = "other"  # type: ignore[misc]

    def test_fields_present(self):
        result = canonicalize_resource("host://cloudhub.pottersquill.com")
        assert hasattr(result, "scheme")
        assert hasattr(result, "path")
        assert hasattr(result, "raw")
        assert hasattr(result, "canonical")
