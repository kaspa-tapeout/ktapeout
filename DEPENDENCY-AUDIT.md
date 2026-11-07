# Dependency audit

This repository contains Rust source and one workspace lockfile. Dependency
status is not a security audit.

The public CI runs `python scripts/check_dependency_audit.py` against the root
workspace lockfile. Its exact advisory IDs and individual expiry dates are in
`dependency-audit-policy.json`. The check fails when an exception expires or
when a new non-ignored advisory appears. The candidate remains a non-clean
dependency audit; the exceptions do not mean the advisories are fixed.

The release review also evaluates vulnerabilities, unsound advisories, and
unmaintained packages against the scoped dispositions below. A zero exit code
from `cargo audit` alone is insufficient because informational warning classes
may be allowed by its default settings.

Running without these explicit owner-approved IDs remains BLOCKED. This command applies only to the exact KTAPEOUT 0.5.0 dependency scope and expiry below; all ten advisories remain visible as accepted. It does not make the strict audit clean.

The current 0.5.0 candidate pins the official Rusty Kaspa `v2.1.0` commit
`01b532e8b553523216471682649693af92f0fd16`. A scoped, time-limited exception
is recorded below.

The TN10 flow adds `kaspa-txscript` and the Kaspa RPC client. Their dependency graph
includes zero-knowledge proof crates (the `risc0` and `ark` families) for which no
feature switch was found in the pinned release; they increase build size and
time. The lockfile holds 508 package entries.

- `RUSTSEC-2026-0306`: `faster-hex 0.9.0` has an AVX2 out-of-bounds read; the
  advisory lists `>=0.10.1` as patched. It remains transitive through the
  official Kaspa `v2.1.0` graph because that release still requires the 0.9
  API line; resolving it requires a Kaspa-compatible dependency patch or a
  documented maintainer decision.
- `RUSTSEC-2021-0145`: `atty 0.2.14` has a potential unaligned read on
  Windows and is unmaintained.
- Unmaintained packages reported for the same lockfile include `async-std`,
  `derivative`, `instant`, `paste`, and `proc-macro-error`.

This notice is intentionally conservative. It does not claim exploitability in
every KTAPEOUT execution path, and it does not replace a maintainer-reviewed
dependency update, compatibility test, or security assessment. Publication is
allowed only under the scoped maintainer exception recorded below; the strict
audit result must continue to be disclosed as non-clean.

## Impact assessment — reassessed 2026-10-20

The strict audit reports ten transitive advisory records. The
public Core, Runtime, Kaspa Verifier and CLI passed locked offline compilation,
serial Clippy with `-D warnings`, and the protocol/public-scope release gates
in this review. Under the maintainer-approved exception, the non-zero strict
dependency-audit result is therefore a disclosed follow-up risk, not a blocker
for this 0.5.0 publication. It must not be described as a clean audit, and the
exception must be removed after the pinned upstream dependency graph is
updated and reverified.

The findings are not a KTAPEOUT protocol-semantic failure. The public verifier
does not call `faster_hex::hex_decode_unchecked`; the Rusty Kaspa source pinned
by this release has no such call in its source tree, and the KTAPEOUT verifier
uses the checked `kaspa_txscript::hex::decode` wrapper. That wrapper allocates a
destination sized from the input and calls checked `faster_hex::hex_decode`.
The dependency is nevertheless present in the transitive Kaspa graph, so this
review does not convert the strict audit to **PASS**: a future upstream or
feature-path change could expose the unsafe API, and the package version is
known to have an unsound public code path.

The `atty` finding is also transitive (through Kaspa's `hexplay`/terminal
formatting path). It is not part of KTAPEOUT signing, profile semantics, or
state-transition verification. The remaining findings are unmaintained
packages rather than demonstrated KTAPEOUT vulnerabilities, but they remain
supply-chain maintenance risk and must be tracked.

Consequently, the practical disposition is:

- **Protocol and verifier behavior:** no evidence of an immediate KTAPEOUT
  correctness or consensus-semantic impact was found in this review.
- **Release security gate:** **APPROVED WITH A SCOPED EXCEPTION**. This is
  not a clean dependency audit and must not be represented as one.
- **Exception scope:** KTAPEOUT 0.5.0 public Core, Runtime, CLI (including the
  `ktape tn10` flow), and offline Verifier builds pinned to the official Rusty
  Kaspa v2.1.0 commit above. The
  release ships a local Testnet-10 signing path that uses a developer-supplied key
  (`ktape tn10 sign`), but no wallet, node, key-storage or key-custody service.
- **Compensating controls:** checked hex-decoding wrappers, no direct
  `hex_decode_unchecked` use in the reviewed source, locked dependency
  versions, offline verification fixtures, no secret material, and a required
  dependency audit before every subsequent release.
- **Scope re-confirmation (2026-10-31):** the release owner re-confirmed this
  exception for the current scope, which now includes the `ktape tn10` planning,
  signing, submission and verification code. `faster-hex 0.9.0` and `atty 0.2.14`
  were already in the dependency graph through the offline Verifier, and the
  `ktape tn10` code calls neither package directly. Rusty Kaspa's internal call
  sites for these packages were not re-audited for the added RPC client and
  transaction code; the compensating controls below and the expiry still apply.
- **Approval and expiry:** this exception was approved for the stated scope on
  2026-10-02. It expires when an official Rusty Kaspa update is available or
  no later than 2026-12-31, whichever comes first.
- **Follow-up:** re-pin the official dependency, regenerate the public
  lockfile, rerun check/clippy/audit, and remove this exception before the next
  release. Retain the approval, advisory list, scope, compensating controls
  and expiry with the release review record.

The assessment is based on the selected lockfile, RustSec advisory records,
the pinned upstream source, and inverse dependency-tree inspection for
`faster-hex 0.9.0` and `atty 0.2.14`.

## Upstream status verified 2026-10-02

The official `kaspanet/rusty-kaspa` remote was checked directly. At review
time, `refs/heads/master` and the newest official release tag `v2.1.0` both
resolve to `01b532e8b553523216471682649693af92f0fd16`; no newer official tag
was available. The v2.1.0 workspace still declares `faster-hex = 0.9.0` and
`hexplay = 0.3.0`. RustSec lists `faster-hex >=0.10.1` as the patched range,
but that version cannot be selected under the upstream `^0.9.0` requirement.
Therefore the upstream situation has not changed the release disposition.

## Remediation order

The advisories are transitive dependencies of the pinned Rusty Kaspa verifier;
they are not direct KTAPEOUT dependencies. The release owner must use this
order when closing the gate:

1. Prefer an official Rusty Kaspa release that moves `faster-hex` to `0.10.1`
   or newer and replaces the unmaintained workflow dependencies.
2. If no official release exists, prepare a reviewed Rusty Kaspa-compatible
   fork. Record its immutable commit, upstream diff, license provenance,
   compatibility tests, and a rollback path before changing the pin.
3. Rebuild the public lockfile, run `cargo check --locked` and
   `cargo clippy --locked --all-targets -- -D warnings`, then rerun this audit.
4. A scoped exception is the last resort. It must name every advisory,
   affected package/version, execution-path impact, compensating controls,
   approver, expiry date, and affected release. A command-line allowlist by itself
   is not a review record.

## Curation reassessment 2026-10-20

The official latest release is v2.1.0; its tag resolves to the exact pinned
commit above. The ten advisory IDs are RUSTSEC-2021-0145,
RUSTSEC-2024-0370, RUSTSEC-2024-0375, RUSTSEC-2024-0384,
RUSTSEC-2024-0388, RUSTSEC-2024-0436, RUSTSEC-2025-0052,
RUSTSEC-2026-0306, RUSTSEC-2024-0449 and RUSTSEC-2026-0441. The strict audit remains non-clean.
The scoped disposition expires at the next official Rusty Kaspa release or
2026-12-31, whichever comes first. All ten advisory exceptions expire no later than 2026-12-31;
the dependency-audit command fails after expiry until the exceptions are
renewed or reassessed. They do not renew automatically.

## Upstream advisory disposition — 2026-10-20

The refreshed RustSec database reports RUSTSEC-2024-0449 for unsafe-libyaml
0.2.11, an unmaintained dependency without a patched release. The selected
official Kaspa v2.1.0 graph brings it through kaspa-core -> log4rs default
features -> serde_yaml. The pinned source is the official v2.1.0 tag commit
01b532e8b553523216471682649693af92f0fd16; the latest official release checked
on 2026-10-20 is still v2.1.0. This scope retains the exact inherited upstream dependency within
the existing scope
(KTAPEOUT 0.5.0 Core, Runtime, Kaspa Verifier and CLI only). This item follows
the same expiry: next official Rusty Kaspa release or 2026-12-31, whichever
comes first. A local Testnet-10 signing path using a developer-supplied key is included.
No wallet, node, key-storage or key-custody service is included.

The audit records ten advisory findings and remains non-clean; the disposition
allows this pinned build without masking the advisory or claiming it was fixed.
It applies only to the recorded version and scope. The current scoped
dependency review passes under the recorded disposition. Report vulnerabilities
as described in SECURITY.md.
See https://rustsec.org/advisories/RUSTSEC-2024-0449.html .

## Additional approved disposition — RUSTSEC-2026-0441

The pinned lockfile contains `pin-utils 0.1.1` transitively through
`async-std 1.13.2 -> workflow-core 0.18.0 -> Rusty Kaspa v2.1.0`.
An offline `cargo update --dry-run -p pin-utils` found no compatible
lockfile-only update. The user approved this single disclosed exception through
2026-12-31. No direct KTAPEOUT use or exploitability is established by this
review; the unmaintained package remains a maintenance risk and is not claimed
to be fixed. The pinned Kaspa revision is unchanged.
