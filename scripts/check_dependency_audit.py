#!/usr/bin/env python3
"""Run cargo-audit with only current, explicitly approved advisory exceptions."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "dependency-audit-policy.json"
ADVISORY_ID = re.compile(r"^RUSTSEC-\d{4}-\d{4}$")


def check_expiry(advisory_id: str, expiry: dt.date, today: dt.date) -> None:
    remaining = (expiry - today).days
    if remaining < 0:
        raise ValueError(f"maintainer exception expired for {advisory_id} on {expiry}")
    if remaining <= 30:
        print(
            f"DEPENDENCY AUDIT: WARNING: exception for {advisory_id} expires on "
            f"{expiry} ({remaining} days remaining); review before expiry.",
            file=sys.stderr,
        )


def main() -> int:
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    if policy.get("schema") != "KTAPEOUT-DEPENDENCY-AUDIT-POLICY-V1":
        raise ValueError("unsupported dependency audit policy schema")
    if policy.get("protocol_semver") != "0.5.0":
        raise ValueError("dependency audit policy scope does not match this candidate")

    today = dt.datetime.now(dt.timezone.utc).date()
    advisories = policy.get("advisories")
    if not isinstance(advisories, list) or not advisories:
        raise ValueError("dependency audit policy must list approved advisory IDs")

    lockfiles = policy.get("lockfiles")
    # One Cargo workspace: only the root lockfile is used by cargo, so it is the only one audited.
    expected_lockfiles = {"Cargo.lock"}
    if not isinstance(lockfiles, list) or set(lockfiles) != expected_lockfiles:
        raise ValueError("dependency audit policy must cover the exact public lockfile set")
    for lockfile in lockfiles:
        if not (ROOT / lockfile).is_file():
            raise ValueError(f"policy lockfile is missing: {lockfile}")

    seen: set[str] = set()
    ignored: list[str] = []
    for advisory in advisories:
        advisory_id = advisory.get("id", "")
        expiry = dt.date.fromisoformat(advisory.get("expires_on", ""))
        if not ADVISORY_ID.fullmatch(advisory_id) or advisory_id in seen:
            raise ValueError(f"invalid or duplicate advisory ID: {advisory_id!r}")
        if not advisory.get("rationale"):
            raise ValueError(f"missing rationale for {advisory_id}")
        check_expiry(advisory_id, expiry, today)
        seen.add(advisory_id)
        ignored.extend(["--ignore", advisory_id])

    for lockfile in lockfiles:
        command = ["cargo", "audit", "--no-fetch", "--deny", "warnings", "--file", lockfile, *ignored]
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
        if result.returncode:
            sys.stderr.write(f"Dependency audit failed for {lockfile}:\n")
            sys.stderr.write(result.stdout)
            sys.stderr.write(result.stderr)
            return result.returncode
    print(
        f"DEPENDENCY AUDIT: PASS ({len(lockfiles)} lockfiles, {len(seen)} "
        "expiring maintainer exceptions); new advisories and expired exceptions fail."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"DEPENDENCY AUDIT: BLOCKED: {error}", file=sys.stderr)
        raise SystemExit(1)
