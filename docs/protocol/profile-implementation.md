# Profile implementation guide

This guide defines the minimum implementation shape for a KTAPEOUT Protocol
0.5.0 Profile. The normative requirements are in
[`spec/KTAPEOUT_0.5.0_NORMATIVE_SPEC.md`](../../spec/KTAPEOUT_0.5.0_NORMATIVE_SPEC.md);
this page explains how the Core, runtime and developer tooling fit together.

## Common Profile boundary

Every Profile implementation MUST expose the same lifecycle concepts:

1. **Identity** — stable `profile_id`, semver, schema version and admission
   status.
2. **State encoding** — canonical input and output shapes, field bounds and
   deterministic serialization.
3. **Transition** — a bounded deterministic function from predecessor state
   and authorized inputs to successor state.
4. **Invariant** — a machine-checkable condition that is evaluated before
   publication and after every transition.
5. **Resources** — explicit maxima for bytes, steps, state elements and
   arithmetic values.
6. **Evidence** — reproducible vectors, artifact/domain hashes and a declared
   proof level.
7. **Capabilities** — an explicit map of supported actions. Unsupported
   actions MUST fail closed.

The implementation may use different algorithms or encodings for different
Profiles, but it MUST NOT use a private identity, resource, admission or
evidence rule. A Profile adapter therefore has the same conceptual methods:
`validate`, `lower`, `simulate`, `verify`, `resourceEnvelope` and
`publishCapabilities`. A method that is not supported is represented as an
explicit capability denial, not as an implicit fallback.

Use the published [Profile Descriptor schema](../../spec/ktapeout-profile-descriptor-v1.schema.json)
and [Profile Invariant schema](../../spec/ktapeout-profile-invariant-v1.schema.json)
when packaging these declarations. They are tooling contracts; the English
0.5.0 specification remains the authority for protocol semantics.

## Profile classes in this release

| Profile | Public role | Admission | Execution meaning |
|---|---|---|---|
| `BooleanNetlistV1` | bounded boolean artifact reference | declared | evaluates the published KTB1 artifact |
| `StateMachineV1` | bounded transition artifact reference | declared | evaluates the published binary state machine |
| `NeuronTile` | bounded primitive transition | TN10-admitted reference | evaluates the canonical primitive manifest and vector |
| `CellFoodConservation` | bounded conservation primitive | TN10-admitted reference | evaluates the canonical primitive manifest, state and event |
| `Life` | local composition projection | local-only | reports a bounded aggregate; it does not execute a composed VM |

The `Life` implementation intentionally remains local-only. Its manifest names
the primitive components that a future composed runtime may bind, but the
current evaluator only computes the documented aggregate projection. It MUST
NOT be described as a consensus composition or publication-capable VM.

`NeuronTile` and `CellFoodConservation` are generic infrastructure primitives,
not applications. An application may build on them in a separate repository,
but application logic, wallets, tests and deployment material are outside this
public release.

## Authoring and admission checklist

Before declaring a new Profile implementation ready, provide:

- a canonical descriptor and invariant declaration;
- a transition equation and state/input/output schema;
- a resource envelope with units and step accounting;
- deterministic vectors covering valid, boundary and rejection cases;
- a stable artifact hash domain and predecessor binding rule;
- a capability map and fail-closed error paths;
- equivalent Rust/Core and tool-layer validation, or a documented reason why
  the tool layer is not an execution authority;
- an admission status that does not exceed the available evidence.

Use the smallest public package that contains the descriptor, implementation,
vectors and developer instructions. Do not copy application projects or local
deployment workspaces into a Profile package.
