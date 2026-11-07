# Package and lock format

The 0.5.0 Application Package manifest is non-consensus, content-addressed
metadata. Its schema is:

```text
spec/ktapeout-application-package-v0.5.0.schema.json
```

The manifest binds `protocol_semver`, application/release/artifact identity,
Profile hashes, execution and settlement modes, provenance, limits and
economics. Optional L1 bindings do not grant signing or broadcast authority.

A lock must pin the concrete Profile/Recipe, runtime, compiler, ABI, adapter,
network policy and dependency digests used by the build. Re-lock whenever any
of those inputs changes. A successful lock is a reproducibility boundary, not
an authorization receipt.

Do not hand-edit hashes or claim that a declared estimate is a fresh Kaspa
quote. Resource and fee reports must preserve their evidence label and source.
