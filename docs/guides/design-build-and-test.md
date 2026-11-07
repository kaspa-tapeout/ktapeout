# Design, Build and Validate

Use this loop for a local unsigned application:

1. Describe the intended state, inputs, outputs, authorities and limits.
2. Select a compatible Profile Package and record its exact digest.
3. Compose a Recipe only from identified components and explicit interfaces.
4. Create a Developer Lock for the Profile/Recipe, compiler, ABI, runtime,
   adapter, network policy and dependency digests.
5. Build the deterministic artifact and inspect its commitments.
6. Run the bounded local vectors and preserve their evidence label.
7. Produce an unsigned plan. To anchor an artifact root on Testnet-10 with your own
   test key, use `ktape tn10` ([guide](publish-on-tn10-with-ktape.md)); other
   signing, broadcast and L1 readback remain external boundaries.

The included JSON examples are teaching fixtures. A local simulation or passing
vector does not establish Mainnet readiness, signer authority or L1 admission.
