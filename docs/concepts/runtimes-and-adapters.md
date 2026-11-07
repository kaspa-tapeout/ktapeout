# Runtimes and adapters

Runtime identities describe delivery capabilities, not protocol semantics.
The default user path is walletless browsing and reads, followed by a
user-selected wallet signature for each L1 state-changing operation. Published
walletless application access is read-only; a walletless write mode is not
supported. Local previews, simulations and drafts belong to development tools
and do not grant an application write capability. Interface bindings expose
only `wallet` and `walletless-read` modes; the latter is valid only for
read-only interfaces. Applications may separately integrate an explicitly
authorized service wallet, with its own disclosed authority; it is not the
platform default. External API side effects use that API's own authentication
and authorization contract.

Adapters are explicit boundaries for a compiler, external shape or readback
source. Each adapter requires its own manifest, evidence and admission rules.
The source-line Native-KAS adapter is outside this minimal public candidate.
Its documented boundary is Profile-only and local; it has no RPC, signer,
private-key or broadcast capability.

For web clients, executing an application package is a client/runtime security
decision, separate from Profile validity and L1 state. A client that executes
packages from different publishers SHOULD isolate the application origin from
the portal and from other applications, bind its delivery bridge to the exact
network/application/release context, and default-deny external resources.
Origin isolation separates DOM and origin-scoped storage; it is not a sandbox
for hostile code or a complete egress boundary. Sibling subdomains may share
cookies scoped to a common parent domain, so clients and applications MUST NOT
treat origin separation as protection for secrets exposed to application code.
Likewise, a CSP `connect-src` allowlist is not a general navigation policy;
clients MUST NOT claim complete egress blocking unless the selected browser
runtime enforces and verifies that exact boundary.
Content hashes prove byte integrity against their declared commitment; they do
not prove that the package is benign or that the commitment is authorized by a
trusted on-chain identity. KTAPEOUT Core does not prescribe a particular web
origin derivation, iframe, Service Worker or hosting vendor. Those mechanisms
belong to the client/runtime implementation and must be described only when
that client ships and verifies them.

The separate SITE/Cloudflare candidate includes an opt-in signed runtime
authorization verifier and a pre-activation user review for first use and
release changes. The checked-in Host policy has an empty publisher list, so
publisher authorization is not active for any application by default. When
configured by a reviewed Host build, its policy binds publisher keys to
applications, networks, permissions and a minimum release sequence; signed
authorization binds those claims to the complete runtime pin. Approval is
remembered locally for the same release tuple, and the route is re-resolved
before activation. This does not authenticate the policy's deployment source
or prove an on-chain controller/Release chain. A separately configured Host may
report `binding_status=VERIFIED_CURRENT_BINDING` only after checking the exact
runtime identity and content commitment against its authenticated current-name
resolution; without that check, binding remains `NOT_CHECKED`. Neither value
proves consensus finality. Publisher authorization is reported separately as
`runtime_authorization_status`; user review alone grants no wallet or decryption
capability. The minimal public checkout does not bundle this application Host.

For browser delivery, keep four facts distinct: the immutable
Package/Release commitment, any separately published Runtime sidecar tuple,
the locator/source from which bytes are read, and the client pin used to start
the selected snapshot. Changing Package-committed bytes follows the Release
upgrade contract. A sidecar may be independently republished only under an
existing contract that binds the exact network/application/release/package
tuple; a successful payload readback does not grant NameClaim authority.
Route-pinned manifest and locator hashes establish descriptor consistency, not
publisher authentication. Hosting or cache repair must not silently mutate a
Release or trigger another L1 write.

## Client-neutral contract surface

A client is an implementation of the public contracts, not an authority layer.
Different clients MAY provide equivalent parsing, planning, inspection or
read-only diagnostics when they preserve the same schemas, canonical encoding,
content hashes, error rules and evidence labels. They MUST NOT silently add
provider assumptions, convert a local result into L1 admission, or treat a
wallet/UI transport as protocol authority.

The current public candidate documents this boundary and provides the Rust
implementation path. Browser, Studio and provider-specific clients remain
separate surfaces unless their source, dependencies and release evidence are
explicitly included in a later candidate.

Never infer a generic L1 adapter from a local compiler or from an adapter name.
