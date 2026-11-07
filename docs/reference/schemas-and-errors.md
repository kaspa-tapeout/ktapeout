# Schemas and Errors Reference

Machine-readable contracts are shipped under [`spec/`](../../spec/README.md).
Use the schema named by the record rather than inferring fields from a UI or a
display example.

Validators should fail closed on an unknown protocol version, malformed
canonical encoding, duplicate fields, unknown fields where strictness is
required, out-of-range counts or bytes, mismatched commitments, and unsupported
network or capability claims. Error identifiers are stable diagnostic outputs;
they do not prove that a network operation occurred.

The Rust Core and CLI expose local validation and deterministic planning. The
external signer/provider boundary must remain explicit in the result and must
not be replaced by a local success message.
