# KTAPEOUT 0.5.0 Machine-Readable Contracts

This directory is the minimal machine-readable protocol surface accompanying
the English developer documentation and Rust Core candidate.

Included files are limited to the Core IDL, Profile/Recipe/Application/Effect
contracts, developer/application lock contracts, the Rust CLI command contract,
error codes, naming vectors, and the published Core record and binding vectors.
They define data shape and canonical inputs; they do not grant signer
authority or prove L1 admission.

The human-readable English specification map remains
`../docs/protocol/specification.md` and is marked
`NORMATIVE — SOLE ENGLISH SPECIFICATION`. The English specification, IDL,
schemas and vectors in this directory define the 0.5.0 public contract.

The specification and its [requirements crosswalk](requirements-crosswalk.md)
are included for developer use. The crosswalk is explanatory and does not
override the normative specification.
