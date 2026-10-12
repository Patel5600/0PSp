#!/usr/bin/env python3
"""Repository documentation and release-gate consistency checks.

This checker is intentionally deterministic and offline. It checks repository-local
Markdown targets and a small set of normative release-gate statements; it does not
claim to validate external URLs, cryptographic theorems, or implementation security.
"""
from __future__ import annotations

import re
from datetime import date, datetime
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_LINK = re.compile(r"\[[^\]]*\]\((?:<([^>]+)>|([^)]*))\)")
ACTIVE_DOCS = (
    Path("README.md"),
    Path("docs/README.md"),
    Path("docs/security/evidence-first-rfc-register.md"),
    Path("docs/security/rfc-01-user-committed-issuance.md"),
    Path("docs/theory/spend-relation-spec.md"),
    Path("docs/security/v2-protocol-security-argument.md"),
    Path("docs/plan/dependency-minimization-and-construction-roadmap.md"),
    Path("docs/audit/chp4.3-identity-invariant-decision-review.md"),
    Path("docs/audit/chp4.4-deterministic-output-id-proposal-review.md"),
    Path("docs/audit/chp4.5-hidden-witness-output-identity-proposal-review.md"),
    Path("docs/audit/chp4.6-output-identity-candidate-and-tests.md"),
    Path("docs/audit/chp4.8-namespace-v2-evm-adapter.md"),
)
REQUIRED_TOKENS = {
    Path("docs/security/evidence-first-rfc-register.md"): (
        "Release gate (all mandatory)",
        "Change-control rule",
        "NO-GO",
        "hidden coin-ID uniqueness",
        "CHp4.3",
    ),
    Path("docs/security/rfc-01-user-committed-issuance.md"): (
        "NO-GO",
        "coin_id",
        "r_nf",
        "deposit",
    ),
    Path("docs/theory/spend-relation-spec.md"): (
        "NO-GO",
        "CommitV2",
        "NullifierV2",
        "same",
    ),
    Path("docs/audit/chp4.3-identity-invariant-decision-review.md"): (
        "proposal for review",
        "I1",
        "I2",
        "I3",
        "I4",
        "NO-GO",
    ),
    Path("docs/audit/chp4.4-deterministic-output-id-proposal-review.md"): (
        "adversarial design review",
        "publicly computable",
        "not mathematically injective",
        "SHA-256 is not Keccak-256",
        "NO-GO",
    ),
    Path("docs/audit/chp4.5-hidden-witness-output-identity-proposal-review.md"): (
        "adversarial specification review",
        "128 bits",
        "36 bytes",
        "not yet a privacy proof",
        "NO-GO",
    ),
    Path("docs/audit/chp4.6-output-identity-candidate-and-tests.md"): (
        "reference candidate implemented",
        "not a privacy proof",
        "namespace",
        "36 bytes",
        "NO-GO",
    ),
    Path("docs/audit/chp4.8-namespace-v2-evm-adapter.md"): (
        "NAMESPACE_V2(L, D, A)",
        "checkpoint hash",
        "not a ZK proof",
        "**Production:** **NO-GO**",
    ),
}


def markdown_files() -> list[Path]:
    return sorted(
        p for p in ROOT.rglob("*.md")
        if not any(part in {".git", ".venv", "venv", "build", "dist"} for part in p.parts)
    )


def extract_target(raw: str) -> str:
    # Ignore an optional Markdown title after the URL. Preserve spaces in <...>.
    raw = raw.strip()
    if raw.startswith("<") and ">" in raw:
        return raw[1:raw.index(">")]
    return raw.split(maxsplit=1)[0] if raw else ""


def check_local_links(files: list[Path]) -> list[str]:
    errors: list[str] = []
    for source in files:
        content = source.read_text(encoding="utf-8")
        for match in MARKDOWN_LINK.finditer(content):
            target = extract_target(match.group(1) or match.group(2) or "")
            if not target:
                continue
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or target.startswith("//"):
                continue
            decoded_path = unquote(parsed.path)
            if decoded_path.startswith("/"):
                resolved = ROOT / decoded_path.lstrip("/")
            elif decoded_path:
                resolved = (source.parent / decoded_path).resolve()
            else:
                resolved = source.resolve()
            try:
                resolved.relative_to(ROOT.resolve())
            except ValueError:
                errors.append(f"{source.relative_to(ROOT)}: link escapes repository: {target}")
                continue
            if not resolved.exists():
                errors.append(f"{source.relative_to(ROOT)}: missing local target: {target}")
        if "github.com/Patel5600/PSp/" in content:
            errors.append(f"{source.relative_to(ROOT)}: stale self-repository URL points to Patel5600/PSp; canonical repository is Patel5600/0PSp")
    return errors


def check_freshness() -> list[str]:
    errors: list[str] = []
    today = date.today()
    reviewed_files = {
        Path("docs/README.md"): r"\*\*Last consistency check:\*\* (\d{4}-\d{2}-\d{2})",
        Path("docs/security/evidence-first-rfc-register.md"): r"\*\*Last reviewed:\*\* (\d{4}-\d{2}-\d{2})",
    }
    for relative, pattern in reviewed_files.items():
        path = ROOT / relative
        if not path.is_file():
            errors.append(f"required reviewed document missing: {relative}")
            continue
        match = re.search(pattern, path.read_text(encoding="utf-8"))
        if not match:
            errors.append(f"{relative}: add the required review/consistency-check date without treating automation as human approval")
            continue
        try:
            reviewed = datetime.strptime(match.group(1), "%Y-%m-%d").date()
        except ValueError:
            errors.append(f"{relative}: invalid review date {match.group(1)!r}")
            continue
        if reviewed > today:
            errors.append(f"{relative}: review date is in the future")
        elif (today - reviewed).days > 90:
            errors.append(f"{relative}: review date is older than 90 days; perform a real review and update it")
    return errors


def check_active_docs() -> list[str]:
    errors: list[str] = []
    for relative in ACTIVE_DOCS:
        path = ROOT / relative
        if not path.is_file():
            errors.append(f"required active document missing: {relative}")
            continue
        text = path.read_text(encoding="utf-8")
        if not text.endswith("\n"):
            errors.append(f"{relative}: missing final newline")
        for token in REQUIRED_TOKENS.get(relative, ()):
            if token not in text:
                errors.append(f"{relative}: missing required release-gate marker {token!r}")
    return errors


def check_fixture() -> list[str]:
    import json

    path = ROOT / "tests/fixtures/hidden_tuple_reuse.json"
    if not path.is_file():
        return ["missing fixture: tests/fixtures/hidden_tuple_reuse.json"]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"fixture JSON invalid: {exc}"]
    errors: list[str] = []
    if data.get("schema_version") != 1:
        errors.append("hidden tuple fixture: unsupported schema_version")
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        errors.append("hidden tuple fixture: cases must be a non-empty list")
    else:
        ids = [case.get("id") for case in cases if isinstance(case, dict)]
        if len(ids) != len(cases) or len(set(ids)) != len(ids):
            errors.append("hidden tuple fixture: every case must be an object with a unique id")
    for required in ("same_tuple_different_salt", "same_coin_id_different_rnf"):
        if not isinstance(cases, list) or required not in {
            case.get("id") for case in cases if isinstance(case, dict)
        }:
            errors.append(f"hidden tuple fixture: missing required case {required}")
    return errors


def main() -> int:
    files = markdown_files()
    errors = check_local_links(files)
    errors.extend(check_active_docs())
    errors.extend(check_freshness())
    errors.extend(check_fixture())
    if errors:
        print(f"Repository integrity: FAIL ({len(errors)} finding(s))")
        for error in errors:
            print(f"::error::{error}")
        return 1
    print(f"Repository integrity: PASS ({len(files)} Markdown files; local targets, active release-gate markers, and invariant fixtures checked)")
    print("Scope: offline/local consistency only; external URL availability and cryptographic security are not established.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
