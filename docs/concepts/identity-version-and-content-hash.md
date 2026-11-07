# Identity, Version and Content Hash

KTAPEOUT keeps four questions separate:

- **Identity** says which object is being referenced (`profile_id`, `recipe_id`,
  runtime or adapter ID).
- **Semantic version** says which compatible behavior is intended
  (`*_semver`).
- **Schema version** says how a record is encoded (`V1` in a schema name).
- **Content hash** says which exact bytes or canonical JSON were selected.

Changing an object ID changes its namespace identity. Changing semantic
behavior requires a new semantic version according to the object's contract.
Changing content without changing the declared identity is invalid when the
object is content-addressed. Never use a display name as a commitment.

Locks and application packages carry the hashes needed to reproduce a build;
they do not turn a local hash into L1 evidence or signer authority.

Registry identity adds a separate binding layer. Keep `application_id`,
`resource_id`, `release_id`, `artifact_id`, `profile_hash`, `covenant_id` and
`instance_outpoint` as distinct fields with the semantics declared by the
selected Profile. In particular, `resource_id` is not a universal alias for a
covenant, release or outpoint. A manifest, trust anchor and live readback must
agree before a client treats a Registry identity as verified.

`ApplicationNameDeedCompactV1` and `ApplicationNameDeedV1` are distinct
Profile families. Their records and evidence are not interchangeable, and a
client MUST NOT silently cast one family into the other.
