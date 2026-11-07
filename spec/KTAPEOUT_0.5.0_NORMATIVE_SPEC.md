# KTAPEOUT Protocol v0.5.0 Specification

Status: **NORMATIVE — SOLE ENGLISH SPECIFICATION**

This document is the sole normative English specification for KTAPEOUT Protocol
0.5.0. Its protocol identifiers, fields, bounds, encoding domains and
requirement language are authoritative for the 0.5.0 release. Implementations
MUST use it together with the machine-readable contracts and vectors published
in this repository.

## 1. Scope and conformance

The capitalized terms MUST, MUST NOT, SHOULD, and MAY are normative. A
conforming v0.5.0 implementation MUST implement the canonical IDL, rejection
rules, domain separation, resource admission, and required vectors for every
feature it advertises.


The Core is deliberately small: it binds L1-observable state, authority,
resources, dependencies, values/assets, and authorized successors. It does not
interpret a circuit equation, neuron model, CPU instruction, biological claim,
or external-device result unless a Profile lowers that fact into a bounded
covenant transition.


KTAPEOUT is an application foundation layer above ordinary Internet transports
and clients, not a replacement for TCP/IP, HTTP, WebAssembly or a general
browser. The intended relationship is:

```text
TCP/IP / HTTP / WebAssembly
        ↓
browsers, wallets and clients
        ↓
KTAPEOUT Application Layer
        ↓
KTAPEOUT Core 0.5.0
        ↓
Kaspa L1
```

KTAPEOUT Core standardizes the smallest common kernel for application facts:
addressable state, verifiable transitions, capabilities, resources, settlement
and lifecycle. Artifact packaging, human-readable naming, Runtime execution,
Studio UX, Browser Extensions, Wallet Connectors, Gateways, circuits, neural
models, VMs and external devices are Profile or tooling concerns unless an
explicit Core record says otherwise.


The Core does not claim that the entire Internet application infrastructure is
production-ready. A conforming implementation may be Core-conformant while its
Profile, L1 Adapter, Toolchain, Runtime, Studio, Extension, Wallet Connector or
Network Admission remains unimplemented or unadmitted.

## 2. Version boundary

KTAPEOUT 0.5.0 is a standalone protocol generation. Every object, plan,
profile descriptor, adapter manifest, and signer request MUST carry
`protocol_id=KTAPEOUT` and `protocol_semver=0.5.0`. Historical or unknown
protocol versions are outside this package and MUST be rejected before
decoding, signing, submission, or state projection. A 0.5.0 record MUST NOT
be represented with an older record layout, trailing extension bytes, or
undocumented optional fields.


## 2.1 Feature-set commitments / Feature

Feature identifiers are ASCII lowercase strings matching
`[a-z0-9][a-z0-9._-]{0,63}`. A feature set contains at most 64 identifiers;
duplicates are rejected. Sort identifiers by their raw UTF-8 bytes. Its root is
SHA-256 of:

```text
KTAPEOUT/0.5.0/FEATURE_SET/V1 || 0x00 || count:uint16_le
|| (length:uint16_le || identifier_utf8)*
```

The digest is computed as:

```text
KTAPEOUT/0.5.0/FEATURE_SET/V1 || 0x00 || count:uint16_le
|| (length:uint16_le || identifier_utf8)*
```

The layout's critical and optional roots MUST be calculated this way. Critical
features are required for validity; an implementation that does not support
one MUST reject. Optional features may be ignored, but MUST NOT be executed or
displayed as active unless supported.


## 3. Core state model / Core

An **Object** is one live covenant UTXO lineage. A **Partition** is an Object
whose stable identity is derived from a `KPartitionLayoutV1` and an index. A
partition's live outpoint and state are authoritative for that partition.


There is no implicit global mutable contract. A collection of independent
partitions is a set of lineages, not a continuously updated global root.
Consumers that require atomic relation between partitions MUST consume the
relevant inputs in one bounded collective transition.


## 4. New canonical records

All records use the v0.5.0 IDL's fixed field order, little-endian integers,
canonical text, bytes32 hashes, fixed-width `u8` enum values, and bounds.
Enum ordinals are frozen by the IDL; enum names are never encoded on the
consensus wire. Every record hash MUST use SHA-256 of
`domain_tag_utf8 || 0x00 || canonical_record_bytes`, with a record-kind-specific
domain tag. State-root algorithms remain Profile-declared and must be bound by
`leaf_encoding_hash` or the relevant Profile descriptor.


### 4.1 `KPartitionLayoutV1`

This immutable deployment record binds `protocol_id`, `protocol_semver`,
critical/optional feature roots, `deployment_id`, `profile_hash`, `layout_id`,
`partition_count`, `partition_id_domain`, `leaf_encoding_hash`, `topology`,
`merge_mode`, `template_root`, `invariant_hash`, `network_policy_class`, and
static maximums. It defines membership and shape; it is not a mutable state
root.

`partition_count`, proof depth, partition state bytes, inputs, outputs, witness
bytes, operations, and compute units MUST be bounded. A raw unbounded list of
partition identifiers is forbidden. Selection is represented by an exact fixed
range or a bounded Merkle commitment whose canonical ordering is defined by the
Profile.

For this Core generation, `max_batch_inputs` and `max_batch_outputs` MUST each
be between 1 and 64 inclusive. A feature set's empty root is a normal computed
hash; the all-zero hash is never a valid feature-set root.

`network_id` MUST be a canonical ASCII identifier matching
`[a-z0-9][a-z0-9._-]{0,63}`. The Layout fields `deployment_id`, `profile_hash`, `layout_id`,
`partition_id_domain`, `leaf_encoding_hash`, `template_root`, `invariant_hash`,
and `network_policy_class` MUST be non-zero commitments. Zero is reserved for a
field only when this specification explicitly assigns it a zero meaning.


The feature-set root is a canonical commitment.
`profile_hash` MUST be the content address of the exact Profile descriptor:
`SHA-256("KTAPEOUT/0.5.0/PROFILE_DESCRIPTOR/V1" || 0x00 ||
JCS(descriptor_without_profile_hash))`. The descriptor schema and all bounded
shape, equation, invariant, capability, exit, proof, and lowering commitments
MUST be fixed before signing. Profile-specific data may be referenced by hash,
but cannot be silently omitted from the descriptor.

`SHA-256("KTAPEOUT/0.5.0/PROFILE_DESCRIPTOR/V1" || 0x00 ||

### 4.2 `KPartitionActionV1`

This record binds one transition class: `LOCAL`, `ATOMIC_BATCH`, or
`MIGRATION`. It includes the layout hash, action nonce, epoch, selector
commitment, ordered input-outpoint root, predecessor-state commitment, ordered
successor root, capability hash, resource-bill hash, policy hash, dependency
commitment, and action kind.


For `LOCAL`, exactly one partition lineage advances. For `ATOMIC_BATCH`, every
input and successor covered by the selector MUST be present in the same
transaction and validated in canonical order. `MIGRATION` follows the separate
migration rules. No action may rely on an off-chain coordinator for validity.


In an action, `layout_hash`, `selector_commitment`, `input_outpoint_root`,
`successor_root`, `capability_hash`, `policy_hash`, `resource_bill_hash`, and
`dependency_root` MUST be non-zero. `previous_state_root` MAY be zero only for
an explicitly declared epoch-0 genesis transition; it MUST be non-zero for a
later epoch. Zero does not mean "not checked".


#### Canonical fact bindings

The following action commitments have protocol-level equations; they are not
arbitrary non-zero labels. Let `H_d(x)` mean
`SHA-256(d || 0x00 || x)`, where `d` is the exact domain shown below. All lists
use the exact lowerer order and the fixed-width encodings from the IDL:

```text
input_outpoint_root = H_d(
  "KTAPEOUT/0.5.0/INPUT_OUTPOINT_ROOT/V1",
  count:uint16_le || (txid:bytes32 || output_index:uint32_le)*
)

successor_root = H_d(
  "KTAPEOUT/0.5.0/SUCCESSOR_ROOT/V1",
  count:uint16_le ||
  (output_bytes_length:uint32_le || output_bytes ||
   lineage_hash:bytes32 || state_root:bytes32)*
)

capability_hash = H_d(
  "KTAPEOUT/0.5.0/CAPABILITY_SET_ROOT/V1",
  count:uint16_le || (capability_hash:bytes32)*
)
```

The generic Core equations above intentionally do not assign a hidden meaning
to `selector_commitment`, `previous_state_root`, or `dependency_root` beyond
their required non-zero/epoch rules. A Profile MUST define the exact bounded
encoding, domain, ordering, and L1-visible facts for each one that it uses:

- `selector_commitment` MUST bind the declared fixed range or Merkle selector;
- `previous_state_root` MUST bind the live predecessor for `LOCAL`, and a
  Profile using `ATOMIC_BATCH` MUST define how the ordered predecessor states
  are aggregated and verified;
- `dependency_root` MUST bind the exact dependency manifest (including the
  empty manifest for a dependency-free Profile) and its artifact/version
  commitments. A non-zero arbitrary label is not a valid dependency binding.

The Profile descriptor MUST contain these algorithms and bounds before signing,
and the deployed L1 adapter MUST recompute or verify every claimed binding from
transaction-visible facts. A Core implementation MUST reject a Profile whose
descriptor omits an algorithm for a field that the Profile claims to use; it
MUST NOT invent a default ordering or treat a hash label as proof.


- `selector_commitment`
- `previous_state_root`


`policy_hash` MUST equal the content address of the active immutable
`NetworkPolicy`; `resource_bill_hash` MUST equal the content address of the
canonical resource bill used for admission. A Core implementation MUST expose
these equations to independent lowerers and verifiers. A deployed covenant MUST
recompute the applicable values from transaction-visible facts rather than trust
the action or UnsignedPlan text.

The digest domain is:
```text
input_outpoint_root = H_d(
  "KTAPEOUT/0.5.0/INPUT_OUTPOINT_ROOT/V1",
  count:uint16_le || (txid:bytes32 || output_index:uint32_le)*
)

successor_root = H_d(
  "KTAPEOUT/0.5.0/SUCCESSOR_ROOT/V1",
  count:uint16_le ||
  (output_bytes_length:uint32_le || output_bytes ||
   lineage_hash:bytes32 || state_root:bytes32)*
)

capability_hash = H_d(
  "KTAPEOUT/0.5.0/CAPABILITY_SET_ROOT/V1",
  count:uint16_le || (capability_hash:bytes32)*
)
```


Before applying a transition, the verifier MUST compare `epoch` and
`action_nonce` with the live predecessor context and MUST compare
`previous_state_root` with the live predecessor state root. A genesis action is
the only exception: it MUST be explicitly admitted at epoch 0 with a zero
`previous_state_root`. A stale nonce, wrong epoch, zero non-genesis root, or
root mismatch is a replay failure and MUST be rejected before authorization.


### 4.3 `KCollectiveSealV1`

The `seal_strength` MUST be exactly one of. A seal MUST also bind its
`previous_seal_hash`; a seal sequence cannot be reordered or replayed. Its
`barrier_mode` is `NONE`, `DIRECT_COVERAGE`, or `L1_PROOF`:

A seal at epoch 0 is the genesis seal and MUST use zero `previous_seal_hash`;
a seal at epoch greater than 0 MUST use a non-zero `previous_seal_hash`.

| Value | Meaning |
|---|---|
| `LOCAL_RECEIPT` | Reports one validated local transition only. |
| `ACCUMULATOR` | Commits to included items only; does not prove completeness or semantics beyond each included item. |
| `FULL_BARRIER` | Proves every member in an explicitly defined bounded epoch set is covered, either by consuming/locking all required predecessors or by an actually L1-verified proof. |

`L1_PROOF` is an evidence label:
|---|---|

An implementation MUST NOT label an `ACCUMULATOR` as a complete snapshot,
global state, final epoch, or proof of all-profile semantics.

`LOCAL_RECEIPT` and `ACCUMULATOR` MUST use `barrier_mode=NONE` and an all-zero
`proof_binding_hash`. `FULL_BARRIER` MUST use either `DIRECT_COVERAGE`, where
the exact required predecessors/locks are verified in the transaction, or
`L1_PROOF`, where a non-zero binding names a verifier actually executed by L1.
Any other combination MUST fail closed.

The Seal fields `layout_hash`, `expected_selector_commitment`,
`included_action_root`, `coverage_commitment`, `state_commitment`,
`authority_hash`, and `resource_bill_hash` MUST be non-zero commitments.
`proof_binding_hash` is zero only for the non-proof combinations explicitly
defined above; a zero seal commitment never means "not checked".

Implementations MUST fail closed.
For `ACCUMULATOR`, `state_commitment` means only the states of the included
actions under the accumulator's declared ordering. It MUST NOT be presented as
the current state of omitted partitions or as a global application root.



## 5. Topology and merge

`topology` is the IDL enum `SINGLETON`, `INDEPENDENT`, or
`BOUNDED_COLLECTIVE`. `merge_mode` is the IDL enum `NONE`, `DISJOINT`,
`ORDERED`, or `REDUCER`; their numeric ordinals, like all other enum ordinals,
are consensus-frozen.

- `INDEPENDENT` permits parallel updates only to distinct live outpoints.
- `DISJOINT` requires proof that selected identities do not overlap.
- `ORDERED` requires the Profile's exact ordering key and forbids permutation.
- `REDUCER` MUST name a fixed, bounded Profile template and may not execute
  arbitrary user-supplied code.



## 6. Authority, successor and replay

Every input covenant MUST validate the relevant predecessor state, capability
scope, nonce/epoch, resource envelope, required foreign-template commitments,
and exact successor output family. Covenant-family admission alone is never
sufficient. Capability scope MUST bind deployment, action class, partition
selector or partition identity, expiry, rights, and nonce.

For a single-use capability, its bound nonce MUST equal `action_nonce` exactly,
and the capability MUST be consumed by that transition. A Profile that uses a
different nonce derivation or a reusable capability MUST publish the deterministic
derivation, scope and replay rule in its Profile descriptor and bind that
descriptor in `profile_hash`; it MUST NOT rely on an implementation convention.



### 6.1 Successor cardinality is Profile-defined

Core does not assume that every application is a singleton. A stateful Profile
MUST declare its successor model and bounded predecessor/successor cardinality
(`SINGLETON_1_TO_1`, `SHARDED_1_TO_1`, `BATCH_N_TO_M`, or `IMMUTABLE`) in the
Profile descriptor or its bound Profile Package, with the descriptor's optional
`successor_contract_hash` binding the machine-readable contract. The deployed L1
path MUST enforce that declared model.
Resolvers and tools MUST NOT infer liveness from an address, receipt order, or
Profile version. For a singleton model, only the successor found and verified
at the pinned tip is live; historical successors remain audit evidence.


Record commitments use the versioned, record-kind-specific domain tags in the
IDL and are intentionally network-independent. Network separation MUST be
applied to the transaction-bound plan, capability, covenant-template binding,
and signer/submitter domain by including protocol version, network identifier,
deployment ID, record kind, and action class. An already-spent UTXO, stale
nonce, invalid epoch, wrong selector, duplicate identity, or unexpected output
MUST fail closed.


## 7. Resource and economic admission

The Core binds resource facts but does not set a permanent fee floor. A plan
MUST bind its `KResourceBillV1` and versioned `NetworkPolicy`; it MUST check
actual transaction mass/compute requirements before signing and reject if any
declared maximum or user `max_fee` is exceeded. `locked_value` and
`network_fee` are distinct and MUST NOT be conflated.


Sparse, event-driven, batching, paging, and chunking are valid Profile
strategies only when their outputs satisfy the same successor and invariant
rules. They cannot silently lower precision or omit required transitions.


## 8. Proofs and external devices

Proof records remain optional. `L1_ZK_VERIFIED` may be used only if the exact
verifier, key/circuit commitment, public-input schema, proof bytes, and state
transition are verified by the deployed L1 path. A hash, trace, attestation,
or external-device report is not a ZK proof.


## 9. Liveness, availability and exits

A valid transition MUST be completable by an authorized participant without a
designated sequencer, browser, indexer, or prover. Profiles MUST define bounded
timeout/recovery/exit semantics and required witness availability. A commitment
to unavailable data is not a usable state transition.


The same rule applies to client products: a Studio, Browser Extension, Gateway,
indexer or Runtime MAY improve discovery, caching, rendering and construction,
but a valid state transition MUST remain independently reconstructible from the
declared inputs, witnesses, policy and L1-visible facts. Client availability is
not consensus availability.


## 10. Release claims

No v0.5.0 Profile may claim `TESTNET_ADMITTED` until its own canonical vectors,
cross-runtime implementation, artifact-specific L1 lowering, forged/replay/
stale tests, bounded resource evidence, and authorized TN10 confirmation are
present. Mainnet claims require separate governance authorization.

The Core release label is independent. The current v0.5.0 repository may claim
`CORE_PROTOCOL / PRODUCTION_CANDIDATE` only for the Core scope covered by its
release manifest; it MUST NOT imply that a generic L1 Adapter, a complete
Profile, the Studio/Extension product, or Mainnet is production-ready.

The release record must include artifact-specific L1 lowering evidence and
forged, replay and stale-input checks.
