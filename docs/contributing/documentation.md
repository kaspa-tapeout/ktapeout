# Documentation contribution guide

English Markdown in `docs/` is the public editing source for developer
documentation. Keep identifiers, JSON keys, CLI flags, hashes, vectors, URLs,
license text and byte strings unchanged.

Version and authority notices belong at the documentation entrypoint and
normative specification. Add page-specific status or prerequisites when they
affect use. Plans and research notes belong in maintainer archives; do not add
them to the default developer navigation.

The English 0.5.0 specification is the sole normative protocol text. Protocol
changes require requirement-to-implementation traceability and conformance
review. Ordinary prose changes require link, language and static
build checks. Do not describe a local estimate, receipt or UI result as L1
confirmation without the corresponding evidence.

Apply [code and API standards](code-standards.md) to public comments, Rust API
documentation, CLI help and examples. Verify commands and relative paths from
a clean public checkout; do not require maintainer-local skills.
