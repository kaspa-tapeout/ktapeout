//! Shared native release components.
//!
//! The default coordinator build exposes the local release modules. A downstream pinned adapter
//! can disable default features and enable `host-free-native-adapter` to link the native release
//! executor without linking `release_workflow`, which embeds the adapter registry. This surface
//! does not by itself make an adapter ready; all declared workflow phases still need implementation.

pub mod name_space;
pub mod name_state_template;
pub mod namespace_issuance_review;
pub mod registered_keys;
pub mod registry_templates;

#[cfg(any(
    feature = "coordinator",
    feature = "adapter-contract-only",
    feature = "host-free-native-adapter"
))]
pub mod release_adapter_contract;
#[cfg(any(feature = "coordinator", feature = "host-free-native-adapter"))]
pub mod release_candidate_binding;
#[cfg(any(feature = "coordinator", feature = "host-free-native-adapter"))]
pub mod release_closure;
#[cfg(any(feature = "coordinator", feature = "host-free-native-adapter"))]
pub mod release_escrow;
#[cfg(any(feature = "coordinator", feature = "host-free-native-adapter"))]
pub mod release_execute;
#[cfg(any(feature = "coordinator", feature = "host-free-native-adapter"))]
pub mod release_name_update;
#[cfg(any(feature = "coordinator", feature = "host-free-native-adapter"))]
pub mod release_native_adapter;
#[cfg(any(feature = "coordinator", feature = "host-free-native-adapter"))]
pub mod release_node_registry;
#[cfg(any(feature = "coordinator", feature = "host-free-native-adapter"))]
pub mod release_readback;
#[cfg(any(feature = "coordinator", feature = "host-free-native-adapter"))]
pub mod release_resolve;
#[cfg(feature = "coordinator")]
pub mod release_workflow;
#[cfg(any(feature = "coordinator", feature = "host-free-native-adapter"))]
pub mod runtime_release_authorization;

#[cfg(feature = "tn10-network")]
pub mod tn10_block_proof;
#[cfg(feature = "tn10-network")]
pub mod tn10_pipeline;

#[cfg(all(feature = "developer-signing", feature = "tn10-network"))]
pub mod tn10_developer_signing;
