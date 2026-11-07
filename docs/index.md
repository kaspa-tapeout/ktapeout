# KTAPEOUT Protocol 0.5.0 Developer Documentation

Status: **Developer Preview / English public documentation**  
Protocol: `0.5.0`  
Network posture: Testnet-10 oriented; not a Mainnet authorization

KTAPEOUT Protocol 0.5.0 defines deterministic transitions over verified
computation Profiles and composable application state on Kaspa. This candidate
supports local contract workflows and a Testnet-10 artifact-root publish flow
(plan, sign with your own test key, submit, verify); it does not execute general
application behavior or provide a complete live publishing stack. The protocol
model is:

```text
Imagine → Compose → KTAPEOUT

Profile → Artifact → Transition → Persistent State
```

## Start here
- [Build a local runtime package](guides/build-runtime-package.md) — deterministic package output without upload or signing.

- [The application platform](platform-overview.md) — the idea-to-address workflow, interaction choices and open ecosystem.
- [Overview](overview.md) — the protocol boundary in one page.
- [Install and verify](getting-started/installation.md) — prerequisites and clean-checkout verification.
- [Scaffold and inspect a local project](getting-started/first-application.md) — unsigned structural preview; does not execute application behavior.
- [Publish an artifact root on TN10 with `ktape`](guides/publish-on-tn10-with-ktape.md) — plan, sign with your own test key, submit and verify; read its validation status first.
- [Storage, integrity and retention](concepts/storage-and-retention.md) — distinguish content identity, locations, authorization, availability and recovery.
- [Plan and verify application storage on TN10](guides/manage-storage-on-tn10.md) — prepare a storage path and collect evidence within the public-candidate boundary.
- [Application discovery images](guides/application-discovery-media.md) — release-bound discovery metadata, presentation resources and receipt-bound directory previews.
- [Naming reference](reference/naming.md) — canonical IDs, aliases, versions and URIs.
- [Identity, versions and content hashes](concepts/identity-version-and-content-hash.md) — how names, revisions and digests stay distinct.
- [State topology and composition](concepts/state-topology-and-composition.md) — bounded transitions, roots and composition boundaries.
- [CLI reference](reference/cli.md) — commands and their authority boundaries.
- [Composition and locks](reference/composition-and-locks.md) — reproducible dependency selection.
- [Schemas and errors](reference/schemas-and-errors.md) — machine-readable contracts and failure classes.
- [Encoding and commitments](protocol/encoding-and-commitments.md) — canonical bytes, hashes and commitment inputs.
- [Author a Profile package](guides/author-a-profile-package.md) — a minimal authoring workflow.
- [Design, build and validate](guides/design-build-and-test.md) — the local development loop.
- [Third-party participation and application access](guides/names-and-application-access.md) — build your own website, gateway, client or ecosystem tools.
- [Core and CLI source](../core/README.md) — the release-shaped Rust implementation.
- [Examples](../examples/README.md) — unsigned deterministic fixtures for local inspection.
- [Capabilities and status](reference/capabilities-and-status.md) — what is local, external, or unavailable.
- [Runtimes and adapters](concepts/runtimes-and-adapters.md) — the client-neutral contract and provider boundary.
- [Protocol specification](protocol/specification.md) — the English specification map and normative-status notice.
- [AI-assisted development](ai/README.md) — the public KTAPEOUT AI Skill and
  safe setup guidance for common coding assistants.

## Choose documentation by task

- **Learn the supported protocol path:** start with [Install and verify](getting-started/installation.md), then [Scaffold and inspect a local project](getting-started/first-application.md).
- **Build a Profile or Package:** use [Author a Profile Package](guides/author-a-profile-package.md); use [Design, Build and Validate](guides/design-build-and-test.md) for the broader local workflow.
- **Understand the model:** read [Overview](overview.md) first, then [Profiles, Packages and Recipes](concepts/profiles-packages-and-recipes.md).
- **Look up exact behavior:** use [CLI](reference/cli.md), [Schemas and Errors](reference/schemas-and-errors.md), and [Capabilities and Status](reference/capabilities-and-status.md); use the [Protocol map](protocol/specification.md) and [Conformance](protocol/conformance.md) for normative details.
- **Publish on TN10:** read [Publish an artifact root on TN10 with `ktape`](guides/publish-on-tn10-with-ktape.md). It anchors an artifact root only; it does not register a name, retain content or provide a complete live publishing stack.

Tutorials explain a first path, guides solve a task, concepts explain design choices, and reference/protocol pages define lookup and conformance details. If pages disagree, follow the authority order in [Document status](#document-status) and the current implementation boundary stated there.

## Document status

Engineering contributions follow the [code and API standards](contributing/code-standards.md).

This directory is the English public documentation source for the 0.5.0
candidate. The English protocol text is the sole normative language for the
0.5.0 release; guides and examples are explanatory only. Identifiers,
field names, hashes, vectors and command flags are retained
exactly. Historical plans and research records are not developer entrypoints.

## Scope boundary

The release is a controlled Testnet-10 prototype and reference implementation.
Local builds, profiles, artifacts and receipts do not grant signing authority,
wallet custody, broadcast authority, Mainnet access, or generic L1 admission.
Those boundaries are explicit in the [capability table](reference/capabilities-and-status.md).
