# Plan and verify application storage on Testnet-10

This guide helps developers prepare a storage path and collect evidence for a
Testnet-10 application. It does not provide a generic upload command. The
0.5.0 public candidate is a local Core/CLI preview whose storage commands are
unsigned planning and receipt checks; storage-provider,
wallet, signer and complete live runtime integrations are separate capabilities.
Check [capabilities and status](../reference/capabilities-and-status.md)
before following an adapter-specific procedure.

## 1. Describe the data before selecting a provider

For each object, record:

- whether it is public, private, or secret;
- whether it can be rebuilt or is the only copy;
- expected size and read frequency;
- retention period and recovery target;
- acceptable providers, regions and cost;
- the digest and schema used to validate a readback.

Do not put secrets, private keys, or recovery codes in a locator, manifest,
transaction payload, log, or provider metadata.

## 2. Freeze the content identity

Build the intended Package/Release and compute its declared digest. Keep the
immutable content identity separate from runtime resource locations. For a
published release, record the network, application, release, package digest,
resource table, and client pin together. A changed package needs the release
maintenance path; moving unchanged bytes may use a location refresh only when
the existing contract allows it and the full resource table remains identical.

The local publication commands are unsigned planning and receipt checks:

```powershell
ktape deploy plan .\my-app\source-manifest.json --network testnet-10
ktape deploy preflight .\my-app\source-manifest.json --network testnet-10
ktape deploy readback .\receipt.json
```

These commands do not upload arbitrary files. `readback` checks the declared
publication receipt contract; it does not, by itself, prove an external
storage provider still serves every resource byte.

Read the structured result fields, not only the top-level `status`: inspect
`data.lifecycle_status`, `data.adapter_status`, `data.external_action`, and
`data.missing_evidence`. In this candidate, `deploy plan` and `deploy preflight`
return `WARNING` while required external evidence is missing. `PLAN_ONLY` and
the missing-evidence list identify what an adapter, node observation, signer
or readback provider must still supply. Even a `PASS` from a future fully
configured local check does not establish chain confirmation or provider
retention.

## 3. Use only an admitted storage path

Select a provider and adapter that are available for the chosen release and
network. Before any external signer or provider acts, verify the exact plan,
network, predecessor, resource bounds, quote, permissions, recipient and
expiry. Keep keys outside KTAPEOUT tooling. A provider upload acknowledgement
is provisional until the exact object can be read back and checked.

The minimal public candidate does not bundle a generic live upload/download
adapter. If your application uses a separately reviewed integration, follow
that integration's own command reference and authorization rules; do not infer
its availability from the protocol documentation alone.

## 4. Verify bytes and state independently

After publication:

1. Read each object from the declared source, using an independent reader when
   the storage contract requires one.
2. Check the byte length, media type, schema and cryptographic digest against
   the locally prepared object.
3. Verify the publication receipt and independent TN10 readback required by
   the selected Profile/adapter.
4. Record which checks passed. Keep byte integrity, publisher authorization,
   chain state and provider availability as separate results.

Do not mark a transaction final from a submission acknowledgement or a single
RPC response. Do not mark content retained because its transaction or locator
was readable once.

## 5. Test update and recovery behavior

### Repair an unavailable payload source

Use this procedure only when the separately reviewed integration supports a
retained-source path; it is not an additional command in this public checkout.

1. Preserve the expected network, application, release, content root and runtime
   authorization. Diagnose the failed read without assuming its cause.
2. Read the complete existing copy over the configured trusted HTTPS connection.
   Verify every resource and recompute the Profile-specific content commitment
   against the authenticated target, not merely a digest supplied by the mirror.
3. Refresh only the permitted source metadata. Preserve the publisher's runtime
   pin and permissions. If the name tuple changed, obtain the exact required
   name-binding statement; an old statement cannot authorize a new Deed.
4. Pin the selected manifest digest, retain current-binding/content checks and
   regenerate the directory projection and any hosting artifact inventory.
   Check receipt hashes against the actual files; do not hand-edit a success flag.
5. Stage and back up the existing target, activate the reviewed metadata and
   read it back. Use a clean browser to check the exact release/pin, isolated
   iframe, activated Service Worker and application behavior.

If committed bytes did not change, this does not inherently require another
content transaction. A source update must still satisfy its existing contract.
Keep old locator files for diagnosis when appropriate; do not retain a broken
payload path as the preferred route when the verified integration selects a
retained manifest. Neither a mirror read nor a cold start proves private-data
restore. Report authenticated save/export/restore as pending when the wallet or
test-space context is unavailable.

### Check release updates and private recovery

For an update, verify whether the package bytes changed. Changed committed
content requires a new Release under its update contract. A location-only
refresh must preserve the complete resource table and bind to the same
network/application/release/package tuple.

For private data, verify encryption before upload and restore from the saved
archive using the intended recovery code only inside the application. A
cross-device recovery claim requires a clean browser profile or device and a
successful restore there. The public 0.5.0 candidate does not provide a
production private-storage or cross-device recovery service, so report such a
test as unavailable unless a separately admitted application integration
supplies it.

## Evidence to keep

Keep the content digest, object size, selected locator, provider/adapter
version, retention terms, upload result, exact readback result, TN10 receipt
and independent readback, and any recovery-test result. Redact credentials,
private data and recovery codes. Label sandbox evidence as sandbox evidence;
it does not establish production availability or retention.
