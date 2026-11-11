# Third-party Websites, Clients and Application Access

Build your own entry into the KTAPEOUT ecosystem: an application website,
read-only explorer, developer tool or compatible client. Your domain can
present the same network-scoped application identity as another gateway.
The project-maintained website is not required to own that identity.

This guide is explanatory. The [0.5.0 specification](../protocol/specification.md)
remains authoritative; `ktape://` is the application URI scheme, not a separate
consensus protocol or a website hosting service.

## Understand the address

An application identity, display name, canonical URI and release are separate
values. The canonical URI has the form:

```text
ktape://<network>/app/<namespace>/<slug>@<release_id>
```

Use the name toolchain to normalize and validate the URI. It rejects ambiguous
case, percent encoding, fragments, queries and unsupported networks. An alias
lookup is useful for discovery, but only a verified, network-scoped record can
establish the current application binding.

Name resolution is read-only unless an explicitly authorized external adapter
performs the publication flow. A browser endpoint, indexer result or local
preview is not by itself Registry or L1 evidence.

Keep the Registry identity tuple explicit in application records:
`application_id`, `resource_id`, `release_id`, `artifact_id`, `profile_hash`,
`covenant_id` and `instance_outpoint` have different meanings. Do not derive
one from another unless the selected Profile contract says so. The Compact
Registry deed and the full deed are separate Profile families; clients MUST
reject a family mismatch instead of applying a compatibility cast.

The current TN10 `ktape.official.adapter.registry` 1.0.0 lineage and its
unverified identity inputs are described in the
[lineage evidence boundary](../../data/registry/official-registry-lineage-evidence-v1.json).
The [`release-evidence/tn10/`](../../release-evidence/tn10/) directory describes
a historical Compact Registry root, not the current lineage. Verify the
current fixed genesis/Profile/policy tuple and Bridge trust anchor, and obtain
fresh readback before treating a name as a trusted development reference.

## Build your own website or gateway

You can host your own frontend and choose your own HTTPS route. For example:

```text
Canonical identity: ktape://testnet-10/app/acme/notebook
Your HTTPS route:   https://gateway.example/app/testnet-10/acme/notebook
```

These are illustrative addresses, not registered applications. The HTTPS
route is your service's convention, not a protocol requirement. A web browser
can open HTTPS directly; opening `ktape://` requires a compatible handler.

An interoperable entry should follow this flow:

1. Parse and validate the URI with the documented naming rules. Keep the
   network and optional release ID explicit.
2. Resolve the binding through your chosen read-only source and verify the
   identity against the applicable Registry manifest and trust anchor.
   For TN10, start with the public identity evidence linked above.
3. Preserve the distinct identity fields and verify the selected release's
   content commitments. Pin an explicit release when reproducibility matters;
   an unpinned address follows the current verified binding.
4. Retrieve content through an explicitly supported storage arrangement.
   A name binding does not ensure that content remains available.
5. Render only what your client supports. Validate Runtime compatibility before
   loading executable content; apply isolation and user-consent controls.
6. Display the network, release and evidence scope. Keep read-only inspection,
   local execution and network-confirmed publication distinguishable.

Start with read-only discovery and inspection. The minimal public package
provides Rust Core/Verifier/CLI sources and public contracts; it does not
bundle a generic web resolver, browser URI handler, Browser SDK, Studio or
provider implementation. Dynamic resolution, Runtime loading and writes
require additional implementations and their own validation. Name and
Profile-specific network writes also require the supported Profile/adapter path,
an external signer and fresh readback. Anchoring an artifact root is described in
[Publish an artifact root on TN10 with `ktape`](publish-on-tn10-with-ktape.md).

## Choose how to participate

| Contribution | Useful first deliverable | Contract to preserve |
|---|---|---|
| Website or gateway | A read-only application directory with canonical URI links | Network-scoped identity, release binding and evidence labels |
| Explorer or indexer | Searchable public Registry records and release inspection | Provenance and readback scope; an index is not authoritative evidence |
| Independent client | A schema reader, artifact inspector or CLI integration | Canonical encoding, hashes, error rules and public schemas |
| Reusable Profile, Package or Recipe | A bounded component with exact dependencies and compatibility documentation | Profile semantics, resource bounds and locked digests; publication admission is separate |
| Runtime or adapter integration | A documented capability boundary and compatibility report | Explicit provider assumptions and Profile-specific admission |
| AI developer tooling | Project instructions or editor integration using the public AI Skill | The same contracts and authority limits as human development |
| Protocol and tooling contributions | A reproducible defect report or focused improvement | The normative specification and contribution standards |

Third-party applications and services belong in their own repositories. The
protocol repository publishes shared contracts and tools, rather than hosting
application implementations. Describe your compatibility and supported
capabilities explicitly; do not imply official endorsement.

## Start with the existing public material

- [Naming reference](../reference/naming.md): canonical IDs and URI rules.
- [Client-neutral contracts](../concepts/runtimes-and-adapters.md): equivalent
  clients and provider boundaries.
- [Schemas and errors](../reference/schemas-and-errors.md): validation inputs.
- [Profile authoring](author-a-profile-package.md) and
  [composition and locks](../reference/composition-and-locks.md): reusable components.
- [AI Skill and setup](../ai/README.md): AI-assisted development.
- [Capabilities and status](../reference/capabilities-and-status.md): what the
  current candidate actually includes.
- [Contribution guidance](../../CONTRIBUTING.md) and
  [MIT License](../../LICENSE): collaboration and reuse terms.
