# Overview

KTAPEOUT is a protocol and toolchain for expressing bounded computation and
state transitions as inspectable application artifacts on Kaspa L1.

## The core model

1. A **Profile** declares bounded semantics, state, resources, vectors and
   transition rules.
2. A verified **Artifact** is deterministic build output bound to the Profile,
   compiler, ABI, dependencies and resource limits.
3. A **Transition** is a bounded state change. A local plan or receipt is not
   an L1 confirmation.
4. **Persistent State** is the application state boundary that can be composed
   with other verified components when the relevant locks and policies agree.

Profiles are the unit of composition. A Recipe is a reusable composition and
workflow object; it is not protocol authority. A Runtime describes an
interaction or execution lane; it is not a Profile. An Adapter lowers or
reads a specific external shape; it is not a replacement for the Core.

## Client-neutral integration boundary

KTAPEOUT contracts are client-neutral: a Rust, Python, TypeScript or other
client may consume the same normative schemas, canonical vectors, identifiers,
hashes and conservative evidence labels. Client code MUST NOT create a second
protocol authority or infer capabilities from a provider, wallet, UI or
transport. Provider-specific reads, signing, submission and live readback stay
behind explicit external boundaries.

The 0.5.0 public candidate ships the Rust Core, verifier and `ktape` CLI as its
reviewed implementation path. Other client surfaces may be developed against
the contracts, but are not implied to be included, production-ready or
admitted merely because they can parse a public artifact.

## Kaspa boundary

Kaspa's DAG provides the network substrate for advancing many deterministic
state transitions over time. KTAPEOUT does not change Kaspa consensus. It
binds application-level state, artifacts and evidence to explicit network and
resource policies.

## What 0.5.0 does not claim

- It is not a Mainnet authorization or production security certification.
- A local artifact is not a signed or broadcast transaction.
- A public RPC response is not, by itself, official Registry authority.
- A Profile or Recipe does not imply arbitrary code execution or arbitrary
  website storage.
- Wallet connection does not imply covenant signing, custody or broadcast.
