# State Topology and Composition

KTAPEOUT Core binds bounded state transitions. A Profile defines the semantics
of one bounded state shape; a Recipe composes already identified components
with explicit interfaces, namespaces and resource policies.

Composition is not an implicit global mutable contract. Each input, dependency,
capability and successor must remain identifiable in the resulting artifact or
lock. A consumer that needs an atomic relation across partitions must use the
declared bounded collective transition rather than relying on client ordering.

The Core does not decide what a circuit, neural model, VM or external device
means. A Profile or adapter must lower that meaning into the bounded contract
before it can be verified.
