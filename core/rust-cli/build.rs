fn main() {
    // The release catalog is embedded by release_workflow.rs. Cargo does not
    // discover include_str! inputs outside the crate automatically, so make
    // registry edits invalidate the Rust CLI and its published catalog.
    println!(
        "cargo:rerun-if-changed=../../studio/application-release-target-adapter-registry.json"
    );

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    if target_os == "windows" && target_env == "msvc" {
        println!("cargo:rustc-link-arg-bin=ktape-name-update-adapter=/Brepro");
    }
}
