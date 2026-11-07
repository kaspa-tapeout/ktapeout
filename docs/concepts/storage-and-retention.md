# Storage, integrity and retention

This page explains how to reason about application bytes in KTAPEOUT 0.5.0.
It is explanatory guidance; protocol schemas and the shipped capability table
remain authoritative.

## Keep four questions separate

| Question | Evidence to check | What that evidence does not establish |
|---|---|---|
| Are these the expected bytes? | Recompute the digest and compare it with the declared content commitment or pinned descriptor. | Who published the commitment, whether the bytes are safe, or whether they will remain available. |
| Is this location allowed for this release? | Validate the release-bound descriptor and the applicable publisher authorization. | That the location is online or that a chain state is final. |
| Was a state transition accepted? | Verify the required receipt and independent Testnet-10 readback for the selected Profile/adapter. | Long-term retention or a recoverable copy on another device. |
| Will the bytes still be available later? | Read the exact object from the storage provider under the retention terms you selected. | Integrity or authority unless you also verify the digest and authorization. |

An address or locator answers **where to try reading**. A digest answers
**which bytes to accept**. Authorization answers **who may make a claim**.
Retention answers **how long a source is expected to keep those bytes**. Do not
use one as a substitute for another.

## Protocol identity and storage location

The Package/Release commitment identifies immutable package content. A
separately published runtime descriptor may identify the resource locations
and client pins used to load a selected snapshot, when the applicable release
contract permits that descriptor. Moving identical bytes to another location
is a location change; changing committed package bytes requires a new Release
under the package's update contract. A locator refresh is valid only when the
complete resource table and its release-bound identity remain unchanged.

For browser delivery, the origin also scopes browser storage. Origin isolation
helps separate application data from other origins, but it is not a backup,
retention guarantee, or security boundary for hostile application code.
Clearing browser data or changing profiles can remove local state.

## Payload and external storage

Do not assume every application file belongs in a transaction payload. A
Profile-specific TN10 adapter can define bounded payload/state transitions and
their receipt requirements. That is an adapter contract, not a generic file
hosting API or a promise that arbitrary bytes fit in a UTXO. External HTTPS,
Arweave, Drive, or other providers have separate upload, access, cost,
availability, and retention behavior. A provider's successful upload response
is not a KTAPEOUT receipt or proof of permanent availability.

The minimal public 0.5.0 candidate provides local Core/CLI workflows, a
Testnet-10 artifact-root flow, and documents the external signer/readback
boundary for other paths. It does not bundle a
generic live storage provider, a production private-persistence service, or a
cross-device recovery service. Check [capabilities and status](../reference/capabilities-and-status.md)
before relying on an adapter described elsewhere in the engineering workspace.

## Retained sources and payload pruning

A transaction payload can stop being available from an ordinary node even when
the current name or state commitment remains readable. A failed block request
alone does not prove pruning is the cause. Configure retained sources before
depending on historical payload availability.

A record may carry a developer-hosted HTTPS locator; this is only a source hint,
not an upload adapter or proof of availability. `record verify` checks the local
record's structure and commitments; it does not fetch the locator. When the Shell
opens a supported runtime, it checks the fetched manifest and declared resource
bytes against their SHA-256 commitments, the content root and the current release
binding. If the committed bytes are unchanged, source repair follows the existing
locator/authorization contract rather than automatically creating a new content
release or L1 write.
Recompute descriptor and directory receipt hashes after metadata changes.
Verify the selected source with a clean browser, including the isolated runtime
and Service Worker; downloading files alone is not a startup test.

One working mirror proves present availability, not independent redundancy or
permanent retention. Successful runtime startup does not prove that private
notes, recovery keys or an archive are available on another device.

## Privacy, backups and recovery

Storage operators should receive only the data their role requires. Encrypt
private content before sending it to an untrusted provider, keep encryption
keys and recovery codes outside that provider, and verify the decrypted result
only in the intended client. A ciphertext digest proves ciphertext integrity;
it does not prove that a usable key or a clean-device restore exists.

Treat cache, persistence and backup as different roles:

- A **cache** may be discarded and rebuilt from an authoritative source.
- **Persistence** is a source the application expects to remain available for
  a declared period.
- A **backup** is an independent copy intended to survive loss of the primary
  device or provider.
- **Recovery** is demonstrated only when the required data and keys can be
  restored in a clean client under the documented procedure.

Never describe same-browser readback as cross-device recovery, or a sandbox
upload as production retention evidence.

## Practical checklist

Before choosing a storage path, record the data's privacy class, whether it is
rebuildable, required retention period, recovery target, maximum size, expected
read pattern, and user-approved cost. Then choose a source and a separate
verification method. The [TN10 storage workflow](../guides/manage-storage-on-tn10.md)
shows how to validate the current public-candidate boundary.
