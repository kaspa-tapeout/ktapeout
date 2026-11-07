# Profiles, Packages and Recipes

## Profile

A Profile is the smallest reusable semantic unit. It defines bounded inputs,
state layout, invariants, resources, interfaces and vectors. A Profile ID and
its semantic version are not the same as its content hash.

## Package

A Profile Package supplies the content needed for verification and locking.
Its digest binds the package material; the Developer Lock records the exact
Profile, compiler, ABI, dependency and network inputs selected for a build.

## Recipe

A Recipe composes existing components and interface bindings. It may include
state namespaces, resource and settlement policy, test vectors and a Recipe
hash. A Recipe cannot silently invent a new Profile or grant L1 authority.
Composition must preserve component identity and explicit boundaries.
