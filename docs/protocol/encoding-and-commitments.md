# Encoding and Commitments

Canonical encoding is part of the protocol contract. The Core IDL, schemas and
vectors define field order, byte limits, enum values, required bindings and
domain-separated commitment inputs.

When a commitment is computed, use the exact protocol domain, canonical field
ordering and declared byte representation. Do not hash a display rendering,
an unordered object, a wider legacy record or an omitted optional boundary.

The published vectors under [`spec/`](../../spec/README.md) are the reference
inputs for the 0.5.0 Core surface. A changed encoding, hash domain, bound or
rejection rule is a protocol change and requires an updated crosswalk and
conformance review.
