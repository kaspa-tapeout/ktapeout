# Composition and Locks Reference

The composition contract is defined by
`spec/ktapeout-composition-recipe-v1.schema.json`. The application package
contract is defined by
`spec/ktapeout-application-package-v0.5.0.schema.json`.

At minimum, a reproducible composition records:

- the exact Profile/Recipe identities and semantic versions;
- component and interface bindings;
- package, artifact and dependency digests;
- runtime, compiler, ABI and adapter selections;
- network and resource policy inputs; and
- the resulting lock or package digest.

Unknown fields, hand-edited digests and unbounded dependencies must be rejected
by the relevant validator. A lock freezes build inputs; it does not authorize a
signature or broadcast.
