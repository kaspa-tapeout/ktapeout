# Naming Reference

This is the shared naming entrypoint for developers, AI tooling, the CLI and
the website. Canonical registry IDs are lowercase ASCII and are separate from
display names, semantic versions and content hashes.

## Canonical object IDs

```text
ktape.<publisher>.profile.<family>.<name>
ktape.<publisher>.recipe.<name>
ktape.runtime.<name>
ktape.<publisher>.adapter.<name>
```

These forms are the creation rule for new canonical registry objects. They are
not a claim that every generic `profile_id` field in the 0.5.0 compatibility
schemas enforces the same namespace. Those fields still accept broader legacy
identifiers so existing packages can be read. A release tool MUST distinguish
the canonical registry-name path from a compatibility package identifier.
Legacy IDs are preserved through explicit aliases; an alias is not a new
canonical object and must not be silently promoted.

## Version and hash responsibilities

- The ID identifies the namespace and object name.
- `*_semver` identifies semantic compatibility for that object.
- A Profile, Package, Recipe, Artifact or Application hash identifies exact
  content or a canonical commitment.
- `V1` in a schema name identifies the format/schema version; it is not a
  request to remove a field's semantic version.

## Applications and URIs

An application identity, its display name and its canonical URI are distinct:

```text
ktape://<network>/app/<namespace>/<slug>
ktape://<network>/app/<namespace>/<slug>@<release_id>
```

Supported networks in the 0.5.0 name toolchain are `testnet-10` and `mainnet`.
URI parsing rejects percent-encoded, mixed-case and ambiguous canonical forms.
An alias query must resolve to exactly one network-scoped record.

## Official names

The string `official` is not self-authenticating. Official status requires the
appropriate signed Registry/TrustRoot/delegation evidence and the declared
readback path. A name lookup or public endpoint alone does not establish it.

## Registry identity and Profile families

Registry records MUST keep these values distinct: `application_id`,
`resource_id`, `release_id`, `artifact_id`, `profile_hash`, `covenant_id`,
`instance_outpoint` and the human-facing `name`. A `resource_id` is not
universally interchangeable with a covenant, release or outpoint. Clients
MUST preserve the declared field semantics and MUST fail closed when an
identity tuple, manifest digest or trust anchor does not match.

`ApplicationNameDeedCompactV1` and `ApplicationNameDeedV1` are different
Profile families. The Compact family is a versioned Registry adapter surface;
it MUST NOT be silently cast to the full deed family or presented as generic
L1 admission. A client may accept a Profile only through its declared
contract, hash and adapter evidence.

For the public Testnet-10 Registry root, the versioned manifest, Bridge trust
anchor and corroborating readback are published in
[`release-evidence/tn10/`](../../release-evidence/tn10/). These files are
identity inputs for development and verification. They do not grant signer
authority, consensus finality or Mainnet status.

## Schema compatibility note

The 0.5.0 schemas intentionally accept wider identifier patterns for
compatibility. New registry objects MUST use the canonical forms above.
Existing package identifiers MAY be read through the compatibility path, but
they MUST NOT be presented as newly created canonical registry IDs. The
validator, object kind and protocol tag must be recorded together.
