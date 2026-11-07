# Build a local runtime package

`ktape package build` turns an application directory into a deterministic
static runtime package that the KTAPEOUT Shell loads directly. It is a local
packaging step: it does not upload bytes, request wallet access, sign,
broadcast, or activate a release.

```powershell
New-Item -ItemType Directory -Force .\out | Out-Null
ktape package build `
  --source .\my-app\site `
  --application-uri demo/starter `
  --entrypoint index.html `
  --output .\out\my-app-package
```

Provide your own `index.html` and put only publishable website files in
`my-app/site/`. `ktape dev workflow` may create `build/`, `package/` or other
project files; those are not automatically suitable for publication. Either
keep them outside the package source directory or package the site before
running the development workflow. Create the output parent directory first.
`ktape init` writes `discovery/metadata.json` at the project root, while package
build reads that file only under `--source`; move it into
`my-app/site/discovery/metadata.json` before packaging (PowerShell:
`Move-Item .\my-app\discovery .\my-app\site\discovery`; Bash:
`mv ./my-app/discovery ./my-app/site/discovery`).

The command currently admits `testnet-10` only. The application URI argument
is the `<namespace>/<slug>` suffix; the manifest records the full
`ktape://testnet-10/app/<namespace>/<slug>` URI.

## Output layout

```text
<output>/runtime/testnet-10/<namespace>/<slug>/<release_id>/
  runtime-manifest.json      KTAPEOUT-STATIC-RUNTIME-MANIFEST-V1
  content-commitment.json    commitment over the runtime payload
  index.html                 files keep their original relative paths
  assets/...
```

Copy the `runtime/` tree to the site root unchanged. The manifest `entrypoint`
is the absolute same-origin path
`/runtime/testnet-10/<namespace>/<slug>/<release_id>/<entrypoint>`.

`package_digest` is SHA-256 over the domain
`KTAPEOUT/0.5.0/STATIC_RUNTIME_PACKAGE/V1` and the canonical JSON of the
schema, network, application URI, relative entrypoint and sorted file records
(`path`, `sha256`, `byte_length`, `media_type`). It does not include
`release_id`. Without `--release-id` the release id equals the package digest;
pass `--release-id <64 lowercase hex>` when the release identity is assigned by
the publish flow. The package digest is the same either way.

`content-commitment.json` uses `sha256-canonical-chunks-v1`. It covers the
runtime payload and excludes itself; the package digest includes its bytes.
Covered JSON must not contain `release_id` or `content_root` fields at any
depth, and covered files must not embed the selected release ID's bytes.

## Discovery V2 and Shell commitment rules

Build this candidate's CLI from source to use Discovery V2. Older CLI binaries
may predate this support. `ktape package build` validates
`discovery/metadata.json` and the local files referenced by its V2 metadata.
Invalid metadata, missing bytes or mismatched digests prevent packaging.
Missing metadata produces a warning and allows site-provided descriptions.
Referenced descriptions and images are extracted into
`assets/application-media/sha256/<digest>` outside the runtime tree. Only
their metadata remains in the runtime commitment. See
[application discovery media](application-discovery-media.md) for limits.

When a route requires a content commitment, a missing commitment prevents
launch. Every runtime-manifest file except the commitment manifest itself
must be covered, or the Shell reports
`CONTENT_COMMITMENT_COVERAGE_INCOMPLETE`. A canonical-chunks commitment
that declares a release ID must match the runtime manifest's release ID,
or the Shell reports `CONTENT_COMMITMENT_RELEASE_MISMATCH`.
This covers declared runtime files, not the entire website or arbitrary
subsequent network requests.

Changing committed presentation metadata requires a new release and an
update to the name's target binding. Mirror upload alone does not change
the commitment. Integrity checks do not prove permanent availability or
on-chain storage of presentation bytes. Directory entries describe verified
receipt snapshots; opening the Shell performs the launch checks again.

Re-running against identical inputs reports `UNCHANGED`; an occupied output
with different bytes is rejected. A failed build removes its staging directory.

## Rules

Limits match the browser verifier, so a package that builds also loads:

| Rule | Limit or behavior |
| --- | --- |
| Files | 1–128 regular files |
| Single file | ≤ 4 MiB |
| Total | ≤ 16 MiB |
| Path | relative, ≤ 256 bytes, no empty/`.`/`..` segments, no spaces, control characters, `\ ? # %` |
| Case | two paths differing only by letter case are rejected |
| Reserved | `runtime-manifest.json` and `content-commitment.json` at the source root are rejected |

The packager fails closed on content that must never be published: any file or
directory whose name starts with `.` (for example `.env`, `.git`, `.npmrc`),
key material (`*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`,
`*.kdbx`, `id_rsa*`, `id_ecdsa*`, `id_ed25519*`, `id_dsa*`) and source maps
(`*.map`). Point `--source` at the build output directory, not the project
root. Symbolic links, special files, a missing entrypoint, and an output
directory inside the source are also rejected. On Windows, creating a
symlink-based fixture may require Developer Mode or elevated privileges; the
packager itself rejects symlink entries when present.

Packaging does not publish a locator or select a storage provider. Continue
with the documented publish flow to review locator identity, publisher
authorization, storage, and activation. A successful package build alone does
not mean that users can resolve or open the application.

## Known limitations

The generated entrypoint is an absolute same-origin path, so deployment below
a non-root site base is not verified. The site's `sw.mjs` precache paths are
also root-relative and currently do not work below a subpath base. Packaging
does not rewrite either behavior.

## Release acceptance boundary

Freeze source and build-script inputs before signing. A host integration must
separately verify the name target and chain readback, current receipt, complete
runtime coverage, file hashes and MIME types without resource redirects, and
publisher authorization plus name-binding statements where required. After
deployment, read back the frozen public bytes and test a cold Shell launch and
independent window. Check directory media at mobile widths and on hover.

Packaging and shared validation are reusable; production signing, protocol
storage and deployment still require a trusted Host integration and scoped
authorization. Test application save/recovery and real devices separately.
Automatic registry enumeration is not implemented. Retiring a test app from a
site directory does not revoke its route or reclaim on-chain deposits.
