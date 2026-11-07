# KTAPEOUT 0.5.0 Requirements Crosswalk

Status: explanatory conformance crosswalk for the normative English
specification. It does not replace or amend that specification.

The authority is the 0.5.0 normative specification named in
`KTAPEOUT_0.5.0_NORMATIVE_SPEC.md`. This table summarizes its requirement
surface for implementers and reviewers.

| Source section | English section | Force | Fields, bounds or invariant | Review status |
|---|---|---|---|---|
| 1 | 1 | MUST | canonical IDL, rejection rules, domain separation, advertised feature vectors | mapped |
| 2 | 2 | MUST / MUST NOT | `protocol_id`, `protocol_semver`, version rejection, no trailing extension bytes | mapped |
| 2.1 | 2.1 | MUST | lowercase feature IDs, maximum 64 identifiers, duplicate rejection, byte-order sorting | mapped |
| 3 | 3 | MUST | bounded Core state, authority, resources, dependencies and successor binding | mapped |
| 4.1 | 4.1 | MUST | `KPartitionLayoutV1` canonical fields and commitment domains | mapped |
| 4.2 | 4.2 | MUST | `KPartitionActionV1`, nonce/epoch, predecessor root, selector and fact bindings | mapped |
| 4.3 | 4.3 | MUST | `KCollectiveSealV1`, barrier mode, seal strength and predecessor binding | mapped |
| 5 | 5 | MUST | topology enum, merge mode and deterministic composition rules | mapped |
| 6 | 6 | MUST | authority, successor cardinality, replay and capability derivation | mapped |
| 7 | 7 | MUST | resource maxima, fee/economic bounds and network policy commitments | mapped |
| 8 | 8 | MUST / MAY | proof status, verifier binding and external-device non-consensus boundary | mapped |
| 9 | 9 | MUST | liveness, availability, exits and bounded reconstruction requirements | mapped |
| 10 | 10 | MUST NOT | release claims must not imply production, Mainnet or audit status without evidence | mapped |

Reviewers should compare each row against the specification paragraphs, IDL,
schemas and vectors, including every numeric limit and error condition. A
heading-level match is not sufficient evidence of equivalence.
