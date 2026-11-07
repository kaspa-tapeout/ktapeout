# Application discovery images

Published resource bundles can provide a separately published media artifact without replacing executable runtime files. The entry site's maintainer can select it as a `CURATED_RESOURCE_ARTIFACT` preview using public resource-readback and application-resolution inputs. The media artifact has its own root; this selection does not mean the application NameClaim commits that media root. A preview does not grant capabilities or change application identity. Opening the application still performs its existing identity verification.

Use this optional path when an application benefits from an icon or a directory
card image. Images are ordinary files in the application's existing content
artifact; they do not add a Profile, permission or naming rule. Adding media to
an already published application can require ordinary content-publication
transactions; their fees depend on the supported publisher and encoded bytes.

## Author and validate

1. Open Studio and use the existing content-folder builder for the application
   directory. Select an optional icon and/or card image. Studio writes the
   package-local `discovery/media.json`, validates and previews the selected
   images, then includes the descriptor and image bytes in the same local
   `OnChainContentV1` artifact.
2. Export that artifact and run the official Rust preflight:
   `ktape app content-preflight .\content-artifact.json --network testnet-10`.

   Preflight binds the descriptor to already verified artifact files. It does
   not decode the image, sign or publish the artifact, or prove a current name
   binding. Browser clients verify image bytes and decode dimensions before
   display.
3. Continue through the application's existing supported package, signer,
   publisher, readback and name-resolution workflow. A local artifact or a
   successful preflight is not an L1 publication receipt. Where no supported
   publisher exists for the application, stop at local validation; do not add a
   media-specific writer.

Images are optional. Use PNG, JPEG or WebP only; SVG, animation and remote URLs
are not accepted. Current limits are 32 KiB / 256×256 for an icon, 64 KiB /
768×432 for a card, 96 KiB of unique image bytes total and 8 KiB for the
descriptor. Image bytes count against the existing content artifact limits and
may increase its storage or publication cost. Include only assets you have the
right to distribute; KTAPEOUT does not establish or verify copyright.

## Optional static directory preview

The Cloudflare Pages workspace can decorate an existing hand-curated directory
card from an explicitly selected public Browser Application Package and
matching readback input. Configure only public inputs in
`config/application-media-sources.json`, then use the existing Pages staging
workflow. The generated catalog is a cached `CURATED_PACKAGE_ARTIFACT` preview:
its tuple checks do not authenticate the receipt or prove that the name still
resolves to the package. It does not create or automatically index application
cards. Opening an application still runs the existing live identity check;
missing or invalid media must never block that route.

An empty source list is valid and keeps the directory on its existing
placeholder images. Do not invent package/receipt inputs or use synthetic
fixtures as production catalog entries.

### Add a preview after publication

If only the directory image needs changing, do not replace the executable
release or rebind its name. Where the application already has a supported
resource publisher, publish the descriptor and image through that path and
retain its readback. The directory maintainer can opt in with
`{"resource_preview":"resource-media.json","resolution_receipt":"readback.json"}`.
This produces a `CURATED_RESOURCE_ARTIFACT` preview with its own media root,
not a claim that NameClaim commits that root. Use a normal application release
update instead when the image must be part of the application's release
commitment. Neither directory path supplies a missing publisher.

See the [CLI reference](../reference/cli.md) for validation semantics. The
maintainer-only Cloudflare workspace README documents the opt-in directory
projection and Pages staging details.
