"""Action type catalog for EP-Governance.

This module defines the canonical set of action types used throughout
the governance system. Action types are used in:
- Policy definitions (the `actions` field)
- Authorization tokens (the `tool` field)
- Transition records
- Attestation `supported_action_types`

The catalog ensures consistency across all components and provides
documentation for each action type.

Categories:
- postgres.execute.* -- PostgreSQL database operations
- shell.exec.* -- Shell command execution
- git.* -- Git operations
- http.* -- HTTP requests
- file.* -- File operations
- docker.* -- Docker container operations
- email.* -- Email operations
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet


@dataclass(frozen=True)
class ActionType:
    """A single action type definition."""

    name: str
    category: str
    description: str
    risk_level: str  # low, medium, high
    reversible: bool


# PostgreSQL actions
POSTGRES_ACTIONS: list[ActionType] = [
    ActionType("postgres.execute.select", "postgres", "Read-only SQL SELECT queries", "low", True),
    ActionType("postgres.execute.insert", "postgres", "SQL INSERT statements", "medium", False),
    ActionType("postgres.execute.update", "postgres", "SQL UPDATE statements", "medium", False),
    ActionType("postgres.execute.delete", "postgres", "SQL DELETE statements", "high", False),
    ActionType("postgres.execute.drop", "postgres", "SQL DROP TABLE/DATABASE statements", "high", False),
    ActionType("postgres.execute.create", "postgres", "SQL CREATE TABLE/INDEX statements", "medium", True),
    ActionType("postgres.execute.alter", "postgres", "SQL ALTER TABLE statements", "high", False),
    ActionType("postgres.execute.opaque", "postgres", "Unclassified SQL (complex/multi-statement)", "high", False),
]

# Shell actions
SHELL_ACTIONS: list[ActionType] = [
    ActionType("shell.exec", "shell", "General shell command execution", "high", False),
    ActionType("shell.exec.ls", "shell", "List directory contents", "low", True),
    ActionType("shell.exec.cat", "shell", "Display file contents", "low", True),
    ActionType("shell.exec.grep", "shell", "Search file contents", "low", True),
    ActionType("shell.exec.find", "shell", "Find files by criteria", "low", True),
    ActionType("shell.exec.head", "shell", "Display first lines of file", "low", True),
    ActionType("shell.exec.tail", "shell", "Display last lines of file", "low", True),
    ActionType("shell.exec.wc", "shell", "Count words/lines/bytes", "low", True),
    ActionType("shell.exec.ps", "shell", "List running processes", "low", True),
    ActionType("shell.exec.df", "shell", "Report disk usage", "low", True),
    ActionType("shell.exec.opaque", "shell", "Unclassified shell command (pipes, redirects, etc.)", "high", False),
]

# Git actions
GIT_ACTIONS: list[ActionType] = [
    ActionType("git.status", "git", "Show working tree status", "low", True),
    ActionType("git.log", "git", "Show commit history", "low", True),
    ActionType("git.diff", "git", "Show changes between commits", "low", True),
    ActionType("git.show", "git", "Show information about a commit", "low", True),
    ActionType("git.branch", "git", "List/create branches", "low", True),
    ActionType("git.fetch", "git", "Download objects from remote", "low", True),
    ActionType("git.pull", "git", "Fetch and merge from remote", "medium", False),
    ActionType("git.push", "git", "Push commits to remote", "medium", False),
    ActionType("git.commit", "git", "Record changes to the repository", "medium", False),
    ActionType("git.reset", "git", "Reset current HEAD to specified state", "high", False),
    ActionType("git.merge", "git", "Join two or more development histories", "medium", False),
    ActionType("git.rebase", "git", "Reapply commits on top of another base tip", "high", False),
    ActionType("git.checkout", "git", "Switch branches or restore files", "medium", False),
]

# HTTP actions
HTTP_ACTIONS: list[ActionType] = [
    ActionType("http.get", "http", "HTTP GET requests", "low", True),
    ActionType("http.post", "http", "HTTP POST requests", "medium", False),
    ActionType("http.put", "http", "HTTP PUT requests", "medium", False),
    ActionType("http.delete", "http", "HTTP DELETE requests", "high", False),
    ActionType("http.patch", "http", "HTTP PATCH requests", "medium", False),
]

# File actions
FILE_ACTIONS: list[ActionType] = [
    ActionType("file.read", "file", "Read file contents", "low", True),
    ActionType("file.write", "file", "Write to a file", "medium", False),
    ActionType("file.delete", "file", "Delete a file", "high", False),
    ActionType("file.move", "file", "Move/rename a file", "medium", False),
    ActionType("file.copy", "file", "Copy a file", "low", True),
    ActionType("file.list", "file", "List directory contents", "low", True),
]

# Docker actions
DOCKER_ACTIONS: list[ActionType] = [
    ActionType("docker.ps", "docker", "List containers", "low", True),
    ActionType("docker.logs", "docker", "Show container logs", "low", True),
    ActionType("docker.inspect", "docker", "Inspect container details", "low", True),
    ActionType("docker.start", "docker", "Start a container", "medium", False),
    ActionType("docker.stop", "docker", "Stop a container", "medium", False),
    ActionType("docker.restart", "docker", "Restart a container", "medium", False),
    ActionType("docker.exec", "docker", "Execute command in a container", "high", False),
    ActionType("docker.rm", "docker", "Remove a container", "high", False),
]

# Email actions
EMAIL_ACTIONS: list[ActionType] = [
    ActionType("email.send", "email", "Send an email message", "medium", False),
    ActionType("email.read", "email", "Read email messages", "low", True),
]


# Complete catalog
ALL_ACTIONS: list[ActionType] = (
    POSTGRES_ACTIONS + SHELL_ACTIONS + GIT_ACTIONS +
    HTTP_ACTIONS + FILE_ACTIONS + DOCKER_ACTIONS + EMAIL_ACTIONS
)

# Name -> ActionType mapping
ACTION_MAP: dict[str, ActionType] = {a.name: a for a in ALL_ACTIONS}

# All known action type names
ALL_ACTION_NAMES: FrozenSet[str] = frozenset(a.name for a in ALL_ACTIONS)

# Action categories
CATEGORIES: FrozenSet[str] = frozenset(a.category for a in ALL_ACTIONS)


def get_action(name: str) -> ActionType | None:
    """Look up an action type by name."""
    return ACTION_MAP.get(name)


def is_known_action(name: str) -> bool:
    """Check if an action type name is in the catalog."""
    return name in ALL_ACTION_NAMES


def get_actions_by_category(category: str) -> list[ActionType]:
    """Get all action types in a category."""
    return [a for a in ALL_ACTIONS if a.category == category]


def get_high_risk_actions() -> list[ActionType]:
    """Get all high-risk action types."""
    return [a for a in ALL_ACTIONS if a.risk_level == "high"]


def get_actions_by_risk(level: str) -> list[ActionType]:
    """Get all action types at a given risk level."""
    return [a for a in ALL_ACTIONS if a.risk_level == level]