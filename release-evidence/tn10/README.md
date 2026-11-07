# Public TN10 identity evidence

These files are the selected, public Testnet-10 identity inputs for the
KTAPEOUT 0.5.0 Compact Registry read path. They let a client locate and
compare the declared Registry root before attempting a provider read.

The manifest and Bridge trust anchor bind the same public tuple:

- network: `testnet-10`
- genesis commitment: `bacb2d6efeaeb4543c44a0b78234c2c07e1f2694c3ab7d7b3ee1f73ccafb0c7d`
- covenant ID: `ec0a43245c97e363ffade6e13778f64e4ab5414641c218bc3e963f54488e6a23`
- genesis outpoint: `7c9c7542890f16a758b5610c277a787f5a43cc37350bb310e494ceda1bd0a850:0`
- manifest digest: `c6fb5611ee713646142018f95f0cf17daa9a2909017e00d375ae6c9bd960325a`

The readback file is corroborating public evidence. It does not grant signer
authority, prove consensus finality, or authorize Mainnet. Clients MUST still
perform their declared live readback and evidence checks, and MUST fail closed
on tuple or manifest-digest mismatches.

These are public Testnet-10 identity materials only. No private key, wallet,
credential, authenticated endpoint or deployment secret is included.
