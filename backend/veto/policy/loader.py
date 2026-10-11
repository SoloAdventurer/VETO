"""Load and fingerprint a policy file."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import yaml

from veto.policy.engine import PolicyError, validate_policy
from veto.policy.lint import MAX_POLICY_CHARS, lint_policy


@dataclass(frozen=True)
class LoadedPolicy:
    raw: dict
    policy_id: str
    version: str   # "<policy_id>@<format version>+<sha256[:12]>"


def load_policy(path: Path | str) -> LoadedPolicy:
    return load_policy_text(Path(path).read_text(encoding="utf-8"))


def load_policy_text(text: str) -> LoadedPolicy:
    """Parse and validate a policy given as text (tenant policies are stored in the database)."""
    if len(text) > MAX_POLICY_CHARS:
        raise PolicyError(f"policy is larger than {MAX_POLICY_CHARS} characters")
    raw = yaml.safe_load(text)
    errors = lint_policy(raw)
    if not errors:
        errors = validate_policy(raw)
    if errors:
        raise PolicyError("; ".join(errors))
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    return LoadedPolicy(raw=raw, policy_id=raw["policy_id"], version=f"{raw['policy_id']}@{raw['version']}+{digest}")
