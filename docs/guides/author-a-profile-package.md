# Author a Profile Package

Start with a bounded semantic contract, not an implementation-specific file.
Define the Profile identity, semantic version, state layout, inputs, outputs,
invariants, resource limits, interfaces and vectors. Keep the package
deterministic and record its provenance.

Validate the package against the Profile contract, compute the package digest,
and create a Developer Lock that names every build input. A package may be
usable by the local toolchain before it is admitted by a network; do not label
local verification as L1 admission.

For a new Profile family, publish its compatibility and unsupported surfaces
alongside the package. Do not reuse an existing canonical ID for incompatible
semantics.
