# Core and application layer

The Core owns canonical bytes, hash domains, bounded parsing, resource
semantics and conformance vectors. Application packages connect Core artifacts
to Profiles, Runtime lanes, adapters and network policy without changing Core
canonical encoding.

Rust is the authority for Core bytes and canonical vectors. TypeScript is the
browser, Studio and Bridge-facing typed boundary. Python is a reference and
compatibility surface and cannot promote local evidence to an L1 fact.

An application package may declare identity, Profile hashes, execution mode,
limits, economics and optional L1 bindings. These declarations are not
authorization. The external signer/provider boundary remains explicit.
