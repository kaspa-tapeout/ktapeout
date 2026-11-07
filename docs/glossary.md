# Glossary

| Term | Meaning |
|---|---|
| Profile | Bounded application/state semantics with explicit contracts, resources and vectors. |
| Package | Content-addressed set of Profile material and provenance inputs used for verification. |
| Recipe | Reusable composition and workflow preset that binds components and interfaces. |
| Runtime | A bounded execution or interaction lane, such as walletless read or user-signed write. |
| Adapter | A content-bound compiler, lowering or readback boundary for a specific external shape. |
| Artifact | Deterministic build output with an identity chain and provenance. |
| Lock | A binding of exact versions, hashes, network policy and dependencies. |
| Receipt | Structured evidence about a local operation or an external readback; its label defines what it proves. |
| Application ID | A content-derived identifier for an application package; it is not a display name. |
| Canonical URI | A network-scoped `ktape://` application address. |
| TN10 | Kaspa Testnet-10. The release is oriented toward this network and remains bounded by its evidence. |
| `LOCAL_ONLY` | The result has no L1 signing or broadcast authority. |
| `PROFILE_ONLY` | The result describes a Profile/artifact shape, not an L1 fact. |
| `L1_VERIFIED` | A result backed by the declared adapter evidence and required readback. |
