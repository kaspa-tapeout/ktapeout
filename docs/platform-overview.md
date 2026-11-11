# Your idea. Your namespace. Your application.

The broader KTAPEOUT platform connects application identity, reusable
components, development tools, testing and on-chain publication. This 0.5.0
candidate provides protocol documentation, local Core/Verifier/CLI workflows and
a Testnet-10 artifact-root publish flow. Name registration for existing TN10
`ktape.official.adapter.registry` 1.0.0 namespaces is not complete in the public CLI: the isolated V6 sovereign-lineage reference path (not the public developer path)
has verified assembly and VM coverage, while the existing `ktape.official.adapter.registry` 1.0.0 path has
not completed an on-chain end-to-end run. Check [capabilities and status](reference/capabilities-and-status.md)
before treating a documented platform step as available in this package.

## Broader platform lifecycle

A protocol supplies the rules. A platform makes those rules useful. KTAPEOUT
connects the steps developers need to turn an idea into a testable, publishable
application.

### 01 — Design

Define your application, choose its network-scoped name, and decide which
actions need authority or settlement. Make state ownership, conflicts, and
resource budgets explicit. A proposed name is not yet a registered binding.

### 02 — Build

Reuse Profiles and Recipes and choose a compatible Runtime. Lock exact Package
digests, compiler, ABI, Runtime, and adapter dependencies. Use the CLI for
repeatable workflows and the Studio where its required capabilities are available.

### 03 — Test

Preview locally, exercise application behavior, and verify artifacts, test
vectors, resource bounds, and component bindings. Local validity and network
publication are separate results.

### 04 — Publish & Bind

Prepare a network-specific plan, authorize it through your signer or provider,
and publish through a supported L1 adapter. Read back the resulting state.
Name registration is a developer capability, but its availability depends on
the namespace contract version; the existing TN10 official registry end-to-end path is
not complete in this preview.

### 05 — Access

Share a canonical KTAPEOUT URI. A compatible HTTPS gateway or browser extension
offers another route to the same application identity. Available interactions
depend on the release and the client's Runtime support.

## Choose the interaction your application needs

### Walletless

Let users browse public content, inspect state, and try local interactions
without connecting a wallet. Choose which actions can be offered to guests.

### Wallet-enabled

Request wallet authorization when an action needs user authority or settlement.
Make the requested action clear and keep signing under the user's control.

---

An application can support both: explore first, connect when needed. Walletless
describes the user experience; published state changes still require the
application's authority and transaction fee arrangements.

## One application identity. More ways to reach it.

The canonical URI names the network, namespace, and application. An HTTPS
gateway maps that identity to a browser-compatible entry. The gateway's domain
is an access point; application identity remains network-scoped.

### Canonical URI

```text
ktape://testnet-10/app/acme/notebook
```

A compatible extension can handle the URI. Add an explicit release ID when you
need to refer to a particular release rather than the current name binding.

### HTTPS entry · illustrative route

```text
https://ktapeout.xyz/app/testnet-10/acme/notebook
```

This is an illustrative address, not a registered application or a verified
live domain deployment. A supported HTTPS entry needs no browser extension.

---

An address does not automatically turn an application into a web page. Content
availability, identity verification, Runtime loading, and authorized actions
are separate capabilities. A namespace field alone does not prove exclusive
ownership of that namespace. See [names and application access](guides/names-and-application-access.md).

## Built to be open

### Your application, your authority

Choose your semantics, interaction model, and authorization rules. Keep
application-specific signing authority with the participants or providers
you designate.

### Reusable by design

Profiles define bounded semantic contracts; Packages carry versioned material;
Recipes declare composition; Runtimes provide the supported execution surface.
Lock exact dependencies and interfaces so others can reproduce them. Composition
does not automatically make separate transitions atomic.

### For humans and AI

Clear commands, structured outputs, and reproducible artifacts support manual
development, automation, and AI-assisted workflows. The same authority boundaries
apply to every caller.

### An ecosystem others can extend

Third parties can build clients, gateways, tools, components, and services
around the published interfaces. The project-maintained website is one entry
into that ecosystem, not the owner of application identity.

Start with the [third-party website and client guide](guides/names-and-application-access.md)
to choose a contribution and understand the integration flow.

### Know what was verified

Keep local tests, network observations, publication receipts, and application
execution understandable. A successful step should explain what it establishes.
State verification and application execution are not interchangeable.

## Available surfaces and release status

The KTAPEOUT 0.5.0 toolchain package remains `TESTNET_PROTOTYPE`, while its
release status matrix marks supported Profile-specific application paths as
`TESTNET_ADMITTED`. Publication requires admission evidence for the specific
Profile and adapter, the declared NetworkPolicy, an external signer, and fresh
readback evidence. These requirements must be checked for the selected path;
the package status alone does not admit an application. This does not authorize a generic L1 adapter, establish consensus
finality, or authorize Mainnet.

The local public candidate is a reviewed Rust Core/CLI, specification,
documentation, and selected tooling surface. The broader release workspace
also contains bounded Studio and Browser SDK contracts, but they are not
included in the minimal public candidate. This website is an access and
documentation entry point rather than a distribution of the complete toolchain.

The website projects its application directory from verified publication
receipts. Each imported application has its own receipt and runtime route.
Descriptions and images come from release-bound discovery metadata when
available; fallback descriptions are marked as site-provided. Host display
policy can hide entries. The shared Shell checks the name binding, release
and committed runtime files again when an application is opened. Applications
still require receipt and route import; automatic on-chain enumeration is
not implemented. Local maintenance and
genesis-provenance commands, together with RuntimeDescriptor validation, check hashes and
evidence; they do not migrate state, sign, broadcast, or grant L1 authority.
Current successor UTXO observations do not authenticate official publisher
authority or establish consensus finality.

See [capabilities and status](reference/capabilities-and-status.md),
[the CLI reference](reference/cli.md), and [publication on TN10](guides/publish-on-tn10-with-ktape.md).

## Keep releases reproducible and recoverable

An upgrade produces a new release. Update the name binding under its controller
policy and retain operation IDs and receipts. When submission status is unknown,
query and recover before submitting again. A name binding is not permanent
content hosting; historical release availability needs its own arrangement.

Use the existing [composition and locks](reference/composition-and-locks.md),
the [CLI's recovery commands](reference/cli.md), and
[naming reference](reference/naming.md). The platform's role is to make these
steps repeatable, not to hide their effects.

## Open source, with room to build your own business

KTAPEOUT's project-authored release code and documentation are licensed under
MIT. You can use, modify, redistribute, and build commercial products with them
under the license terms. Third-party components retain their own licenses;
the license does not grant ownership of project branding or third-party work.

[Read the MIT License](/LICENSE).

Software licensing and network costs are separate. Transactions, name operations,
storage arrangements, and hosting may have costs determined by the selected
network and services.

## Start building

- [Build a first local application](getting-started/first-application.md).
- [Design, build and validate](guides/design-build-and-test.md).
- [AI-assisted development](ai/README.md).
- [The protocol specification](protocol/specification.md) is authoritative;
  this platform introduction is explanatory.
