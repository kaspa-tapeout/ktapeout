//! Offline developer signing. Secret material never crosses this module's boundary.
//!
//! The caller supplies public plan data and a local input stream; this module has no transport.
use crate::tn10_pipeline::{attach_signature, import_signature, signing_summary, Error};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

const MAX_SECRET_BYTES: u64 = 128;

/// A fixed 32-byte hexadecimal secret, optionally followed by whitespace.
/// It is deliberately neither serializable nor printable.
struct SecretMaterial(Zeroizing<[u8; 32]>);

impl SecretMaterial {
    fn read(reader: impl Read) -> Result<Self, Error> {
        let mut encoded = Zeroizing::new(Vec::with_capacity(MAX_SECRET_BYTES as usize + 1));
        reader
            .take(MAX_SECRET_BYTES + 1)
            .read_to_end(&mut encoded)
            .map_err(|_| "TN10_SECRET_INPUT_UNREADABLE")?;
        if encoded.len() as u64 > MAX_SECRET_BYTES {
            return Err("TN10_SECRET_INPUT_TOO_LARGE".into());
        }
        let text = std::str::from_utf8(&encoded)
            .map_err(|_| "TN10_SECRET_FORMAT_INVALID")?
            .trim();
        if text.len() != 64 {
            return Err("TN10_SECRET_FORMAT_INVALID".into());
        }
        let mut decoded = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(text, decoded.as_mut()).map_err(|_| "TN10_SECRET_FORMAT_INVALID")?;
        Ok(Self(decoded))
    }

    fn file(path: &Path) -> Result<Self, Error> {
        let before = fs::symlink_metadata(path).map_err(|_| "TN10_SECRET_FILE_UNREADABLE")?;
        if before.file_type().is_symlink() || !before.is_file() {
            return Err("TN10_SECRET_FILE_UNSAFE".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if before.file_attributes() & 0x400 != 0 {
                return Err("TN10_SECRET_FILE_UNSAFE".into());
            }
        }
        if before.len() > MAX_SECRET_BYTES {
            return Err("TN10_SECRET_INPUT_TOO_LARGE".into());
        }
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(0x00200000);
        }
        let file = options.open(path).map_err(|_| "TN10_SECRET_FILE_UNSAFE")?;
        let opened = file.metadata().map_err(|_| "TN10_SECRET_FILE_UNREADABLE")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if before.ino() != opened.ino()
                || before.dev() != opened.dev()
                || opened.mode() & 0o077 != 0
            {
                return Err("TN10_SECRET_FILE_PERMISSIONS_UNSAFE".into());
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if !opened.is_file()
                || opened.len() > MAX_SECRET_BYTES
                || opened.file_attributes() & 0x400 != 0
            {
                return Err("TN10_SECRET_FILE_UNSAFE".into());
            }
            eprintln!(
                "Warning: Windows key-file ACLs are not validated. Restrict access to your account before use; prefer --key-stdin if unsure."
            );
        }
        Self::read(file)
    }
}

#[cfg(windows)]
mod terminal {
    use super::Error;
    type Handle = *mut std::ffi::c_void;
    #[link(name = "Kernel32")]
    extern "system" {
        fn GetStdHandle(kind: u32) -> Handle;
        fn GetConsoleMode(handle: Handle, mode: *mut u32) -> i32;
        fn SetConsoleMode(handle: Handle, mode: u32) -> i32;
    }
    pub(super) struct NoEcho {
        handle: Handle,
        mode: u32,
    }
    impl NoEcho {
        pub(super) fn new() -> Result<Self, Error> {
            let mut mode = 0;
            // SAFETY: standard input is borrowed; the mode pointer is initialized and writable.
            let handle = unsafe { GetStdHandle((-10i32) as u32) };
            if unsafe { GetConsoleMode(handle, &mut mode) } == 0
                || unsafe { SetConsoleMode(handle, mode & !4) } == 0
            {
                return Err("TN10_HIDDEN_INPUT_UNAVAILABLE_USE_KEY_FILE".into());
            }
            Ok(Self { handle, mode })
        }
    }
    impl Drop for NoEcho {
        fn drop(&mut self) {
            unsafe { SetConsoleMode(self.handle, self.mode) };
        }
    }
}

#[cfg(unix)]
mod terminal {
    use super::Error;
    pub(super) struct NoEcho(libc::termios);
    impl NoEcho {
        pub(super) fn new() -> Result<Self, Error> {
            // SAFETY: termios is initialized by tcgetattr before it is read.
            let mut mode = std::mem::MaybeUninit::<libc::termios>::uninit();
            if unsafe { libc::tcgetattr(libc::STDIN_FILENO, mode.as_mut_ptr()) } != 0 {
                return Err("TN10_HIDDEN_INPUT_UNAVAILABLE_USE_KEY_FILE".into());
            }
            let original = unsafe { mode.assume_init() };
            let mut hidden = original;
            hidden.c_lflag &= !libc::ECHO;
            if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &hidden) } != 0 {
                return Err("TN10_HIDDEN_INPUT_UNAVAILABLE_USE_KEY_FILE".into());
            }
            Ok(Self(original))
        }
    }
    impl Drop for NoEcho {
        fn drop(&mut self) {
            unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.0) };
        }
    }
}

fn interactive_secret() -> Result<SecretMaterial, Error> {
    let _guard = terminal::NoEcho::new()?;
    eprintln!("Enter a 32-byte hexadecimal TN10 secret (input hidden):");
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_SECRET_BYTES as usize + 1));
    let mut input = io::stdin().lock();
    loop {
        let mut byte = Zeroizing::new([0u8; 1]);
        if input
            .read(byte.as_mut())
            .map_err(|_| "TN10_SECRET_INPUT_UNREADABLE")?
            == 0
            || byte[0] == b'\n'
        {
            break;
        }
        bytes.push(byte[0]);
        if bytes.len() as u64 > MAX_SECRET_BYTES {
            return Err("TN10_SECRET_INPUT_TOO_LARGE".into());
        }
    }
    eprintln!();
    SecretMaterial::read(io::Cursor::new(bytes.as_slice()))
}

/// Create an offline partial-signature packet for only the roles owned by this key.
/// The exact terminal phrase is part of the API so callers cannot accidentally
/// reuse the legacy `--yes` path as native-registration approval.
pub fn sign_native_registration_partial(
    plan: &Value,
    authorization: &Value,
    secret: [u8; 32],
    now_unix: u64,
    confirmation: &str,
) -> Result<Value, Error> {
    crate::tn10_pipeline::verify_native_registration_authorization(plan, authorization, now_unix)?;
    let expected_confirmation = format!("SIGN {}", plan["plan_sha256"].as_str().unwrap_or(""));
    if confirmation != expected_confirmation {
        return Err("TN10_NATIVE_SIGN_CONFIRMATION_REQUIRED".into());
    }
    let material = SecretMaterial(Zeroizing::new(secret));
    let mut scalar =
        SecretKey::from_slice(material.0.as_ref()).map_err(|_| "TN10_SECRET_FORMAT_INVALID")?;
    let secp = Secp256k1::new();
    let pair = ErasingPair(Keypair::from_secret_key(&secp, &scalar));
    scalar.non_secure_erase();
    let signer_public_key = hex::encode(pair.0.x_only_public_key().0.serialize());
    let requests = crate::tn10_pipeline::native_registration_signature_requests(plan)?;
    let mut grouped = BTreeMap::<(usize, String), (Vec<String>, [u8; 32])>::new();
    for request in requests["requests"]
        .as_array()
        .ok_or("TN10_NATIVE_SIGNATURE_REQUESTS_INVALID")?
    {
        if request["signer_public_key"].as_str() != Some(signer_public_key.as_str()) {
            continue;
        }
        let input_index = request["input_index"]
            .as_u64()
            .and_then(|index| usize::try_from(index).ok())
            .ok_or("TN10_NATIVE_SIGNATURE_REQUESTS_INVALID")?;
        let role = request["role"]
            .as_str()
            .ok_or("TN10_NATIVE_SIGNATURE_REQUESTS_INVALID")?
            .to_owned();
        let sighash_bytes = hex::decode(
            request["sighash"]
                .as_str()
                .ok_or("TN10_NATIVE_SIGNATURE_REQUESTS_INVALID")?,
        )?;
        let sighash: [u8; 32] = sighash_bytes
            .try_into()
            .map_err(|_| "TN10_NATIVE_SIGNATURE_REQUESTS_INVALID")?;
        let entry = grouped
            .entry((input_index, signer_public_key.clone()))
            .or_insert_with(|| (Vec::new(), sighash));
        if entry.1 != sighash || entry.0.contains(&role) {
            return Err("TN10_NATIVE_SIGNATURE_REQUESTS_INVALID".into());
        }
        entry.0.push(role);
    }
    if grouped.is_empty() {
        return Err("TN10_NATIVE_SIGNER_NOT_A_PLAN_ROLE".into());
    }
    let mut signatures = Vec::with_capacity(grouped.len());
    for ((input_index, public_key), (mut roles, sighash)) in grouped {
        roles.sort();
        let signature = secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash), &pair.0);
        secp.verify_schnorr(
            &signature,
            &Message::from_digest(sighash),
            &pair.0.x_only_public_key().0,
        )
        .map_err(|_| "TN10_NATIVE_SIGNATURE_SELF_CHECK_FAILED")?;
        signatures.push(serde_json::json!({
            "input_index":input_index,
            "signer_public_key":public_key,
            "roles":roles,
            "sighash_type":1,
            "sighash":hex::encode(sighash),
            "signature":hex::encode(signature.as_ref())
        }));
    }
    let authorization_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(authorization)?));
    Ok(serde_json::json!({
        "schema":"KTAPEOUT-TN10-NATIVE-PARTIAL-SIGNATURES-V1",
        "network":"testnet-10",
        "native_plan_hash":plan["plan_sha256"],
        "authorization_sha256":authorization_sha256,
        "signer_public_key":signer_public_key,
        "signatures":signatures,
        "witness_assembly":"PENDING_COVENANT_CONTEXT",
        "broadcast":false
    }))
}

/// Derive the supplied key's public identity and compare it with every role in
/// the immutable native plan. This review data contains no secret bytes.
pub fn native_registration_key_review(plan: &Value, secret: [u8; 32]) -> Result<Value, Error> {
    if !matches!(
        plan["schema"].as_str(),
        Some("KTAPEOUT-TN10-NATIVE-CHILD-REGISTRATION-PLAN-V3")
            | Some("KTAPEOUT-TN10-NATIVE-OWNER-TARGET-PLAN-V1")
    ) {
        return Err("TN10_NATIVE_PLAN_VERSION_UNSUPPORTED".into());
    }
    crate::tn10_pipeline::native_registration_signature_requests(plan)?;
    let material = SecretMaterial(Zeroizing::new(secret));
    let mut scalar =
        SecretKey::from_slice(material.0.as_ref()).map_err(|_| "TN10_SECRET_FORMAT_INVALID")?;
    let secp = Secp256k1::new();
    let pair = ErasingPair(Keypair::from_secret_key(&secp, &scalar));
    scalar.non_secure_erase();
    let derived_public_key = hex::encode(pair.0.x_only_public_key().0.serialize());
    let role_keys = plan["role_public_keys"]["roles"]
        .as_object()
        .filter(|roles| !roles.is_empty())
        .ok_or("TN10_NATIVE_ROLE_KEYS_INVALID")?;
    let planned_keys = role_keys
        .iter()
        .map(|(role, value)| {
            let public_key = value["public_key"]
                .as_str()
                .ok_or("TN10_NATIVE_ROLE_KEYS_INVALID")?;
            let bytes: [u8; 32] = hex::decode(public_key)?
                .try_into()
                .map_err(|_| "TN10_NATIVE_ROLE_KEYS_INVALID")?;
            secp256k1::XOnlyPublicKey::from_slice(&bytes)
                .map_err(|_| "TN10_NATIVE_ROLE_KEYS_INVALID")?;
            Ok((role.clone(), public_key.to_owned()))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let unique_keys = planned_keys
        .iter()
        .map(|(_, key)| key.clone())
        .collect::<BTreeSet<_>>();
    let role_checks = planned_keys
        .iter()
        .map(|(role, planned_public_key)| {
            serde_json::json!({
                "role":role,
                "planned_public_key":planned_public_key,
                "derived_public_key":derived_public_key,
                "matches":planned_public_key == &derived_public_key
            })
        })
        .collect::<Vec<_>>();
    let matching_roles = planned_keys
        .iter()
        .filter(|(_, public_key)| public_key == &derived_public_key)
        .map(|(role, _)| role.clone())
        .collect::<Vec<_>>();
    Ok(serde_json::json!({
        "derived_public_key":derived_public_key,
        "identity_mode":if unique_keys.len() == 1 {"SAME_KEY"} else {"DIFFERENT_KEY"},
        "role_checks":role_checks,
        "matching_roles":matching_roles
    }))
}

/// Validate and combine one partial packet per participating key. Every role
/// must occur exactly once and its Schnorr signature must match that role's
/// plan-bound input sighash. Covenant witness assembly remains a separate step.
pub fn combine_native_registration_partials(
    plan: &Value,
    authorization: &Value,
    partials: &[Value],
    now_unix: u64,
) -> Result<Value, Error> {
    crate::tn10_pipeline::verify_native_registration_authorization(plan, authorization, now_unix)?;
    if partials.is_empty() {
        return Err("TN10_NATIVE_PARTIALS_REQUIRED".into());
    }
    let requests = crate::tn10_pipeline::native_registration_signature_requests(plan)?;
    let expected_authorization_hash =
        hex::encode(Sha256::digest(serde_json::to_vec(authorization)?));
    let mut required = BTreeMap::<(usize, String), (String, [u8; 32])>::new();
    for request in requests["requests"]
        .as_array()
        .ok_or("TN10_NATIVE_SIGNATURE_REQUESTS_INVALID")?
    {
        let input_index = request["input_index"]
            .as_u64()
            .and_then(|value| usize::try_from(value).ok())
            .ok_or("TN10_NATIVE_SIGNATURE_REQUESTS_INVALID")?;
        let role = request["role"]
            .as_str()
            .ok_or("TN10_NATIVE_SIGNATURE_REQUESTS_INVALID")?
            .to_owned();
        let public_key = request["signer_public_key"]
            .as_str()
            .ok_or("TN10_NATIVE_SIGNATURE_REQUESTS_INVALID")?
            .to_owned();
        let sighash: [u8; 32] = hex::decode(
            request["sighash"]
                .as_str()
                .ok_or("TN10_NATIVE_SIGNATURE_REQUESTS_INVALID")?,
        )?
        .try_into()
        .map_err(|_| "TN10_NATIVE_SIGNATURE_REQUESTS_INVALID")?;
        if required
            .insert((input_index, role), (public_key, sighash))
            .is_some()
        {
            return Err("TN10_NATIVE_SIGNATURE_REQUESTS_INVALID".into());
        }
    }
    let mut covered = BTreeSet::<(usize, String)>::new();
    let mut combined = Vec::with_capacity(required.len());
    let secp = Secp256k1::verification_only();
    for packet in partials {
        if packet["schema"] != "KTAPEOUT-TN10-NATIVE-PARTIAL-SIGNATURES-V1"
            || packet["network"] != "testnet-10"
            || packet["native_plan_hash"] != plan["plan_sha256"]
            || packet["authorization_sha256"] != expected_authorization_hash
        {
            return Err("TN10_NATIVE_PARTIAL_BINDING_MISMATCH".into());
        }
        let packet_public_key = packet["signer_public_key"]
            .as_str()
            .ok_or("TN10_NATIVE_PARTIAL_INVALID")?;
        let public_key_bytes: [u8; 32] = hex::decode(packet_public_key)?
            .try_into()
            .map_err(|_| "TN10_NATIVE_PARTIAL_PUBLIC_KEY_INVALID")?;
        let public_key = secp256k1::XOnlyPublicKey::from_slice(&public_key_bytes)
            .map_err(|_| "TN10_NATIVE_PARTIAL_PUBLIC_KEY_INVALID")?;
        let signatures = packet["signatures"]
            .as_array()
            .filter(|values| !values.is_empty())
            .ok_or("TN10_NATIVE_PARTIAL_INVALID")?;
        for item in signatures {
            if item["signer_public_key"].as_str() != Some(packet_public_key)
                || item["sighash_type"].as_u64() != Some(1)
            {
                return Err("TN10_NATIVE_PARTIAL_INVALID".into());
            }
            let input_index = item["input_index"]
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .ok_or("TN10_NATIVE_PARTIAL_INVALID")?;
            let sighash: [u8; 32] = hex::decode(
                item["sighash"]
                    .as_str()
                    .ok_or("TN10_NATIVE_PARTIAL_INVALID")?,
            )?
            .try_into()
            .map_err(|_| "TN10_NATIVE_PARTIAL_INVALID")?;
            let signature_bytes = hex::decode(
                item["signature"]
                    .as_str()
                    .ok_or("TN10_NATIVE_PARTIAL_INVALID")?,
            )?;
            let signature = secp256k1::schnorr::Signature::from_slice(&signature_bytes)
                .map_err(|_| "TN10_NATIVE_PARTIAL_SIGNATURE_INVALID")?;
            secp.verify_schnorr(&signature, &Message::from_digest(sighash), &public_key)
                .map_err(|_| "TN10_NATIVE_PARTIAL_SIGNATURE_INVALID")?;
            let roles = item["roles"]
                .as_array()
                .filter(|roles| !roles.is_empty())
                .ok_or("TN10_NATIVE_PARTIAL_INVALID")?;
            let mut packet_roles = BTreeSet::new();
            for role in roles {
                let role = role.as_str().ok_or("TN10_NATIVE_PARTIAL_INVALID")?;
                if !packet_roles.insert(role.to_owned()) {
                    return Err("TN10_NATIVE_PARTIAL_DUPLICATE_ROLE".into());
                }
                let key = (input_index, role.to_owned());
                let (expected_key, expected_sighash) = required
                    .get(&key)
                    .ok_or("TN10_NATIVE_PARTIAL_ROLE_NOT_IN_PLAN")?;
                if expected_key != packet_public_key || expected_sighash != &sighash {
                    return Err("TN10_NATIVE_PARTIAL_ROLE_BINDING_MISMATCH".into());
                }
                if !covered.insert(key) {
                    return Err("TN10_NATIVE_PARTIAL_DUPLICATE_SIGNATURE".into());
                }
                combined.push(serde_json::json!({
                    "input_index":input_index,
                    "role":role,
                    "signer_public_key":packet_public_key,
                    "sighash_type":1,
                    "sighash":hex::encode(sighash),
                    "signature":hex::encode(&signature_bytes)
                }));
            }
        }
    }
    if covered.len() != required.len() {
        return Err("TN10_NATIVE_PARTIAL_SET_INCOMPLETE".into());
    }
    combined.sort_by(|left, right| {
        left["input_index"]
            .as_u64()
            .cmp(&right["input_index"].as_u64())
            .then_with(|| left["role"].as_str().cmp(&right["role"].as_str()))
    });
    let transaction =
        crate::tn10_pipeline::assemble_native_registration_transaction(plan, &combined)?;
    Ok(serde_json::json!({
        "schema":"KTAPEOUT-TN10-NATIVE-SIGNATURES-AGGREGATE-V1",
        "network":"testnet-10",
        "native_plan_hash":plan["plan_sha256"],
        "authorization_sha256":expected_authorization_hash,
        "plan":plan,
        "authorization":authorization,
        "signatures":combined,
        "transaction":transaction,
        "witness_assembly":"ASSEMBLED_TOCCATA_INPUTS",
        "broadcast":false
    }))
}

/// Revalidate an assembled native transaction at the submit boundary. The aggregate carries the
/// plan and user authorization so submit can independently verify every partial signature and
/// rebuild the witness transaction before it enters the existing submission state machine.
pub fn verify_native_registration_aggregate(
    aggregate: &Value,
    now_unix: u64,
) -> Result<Value, Error> {
    if aggregate["schema"] != "KTAPEOUT-TN10-NATIVE-SIGNATURES-AGGREGATE-V1"
        || aggregate["network"] != "testnet-10"
        || aggregate["witness_assembly"] != "ASSEMBLED_TOCCATA_INPUTS"
        || aggregate["broadcast"] != false
    {
        return Err("TN10_NATIVE_AGGREGATE_INVALID".into());
    }
    let plan = &aggregate["plan"];
    let authorization = &aggregate["authorization"];
    crate::tn10_pipeline::verify_native_registration_authorization(plan, authorization, now_unix)?;
    if aggregate["native_plan_hash"] != plan["plan_sha256"]
        || aggregate["authorization_sha256"]
            != hex::encode(Sha256::digest(serde_json::to_vec(authorization)?))
    {
        return Err("TN10_NATIVE_AGGREGATE_BINDING_MISMATCH".into());
    }
    let signatures = aggregate["signatures"]
        .as_array()
        .filter(|items| !items.is_empty())
        .ok_or("TN10_NATIVE_AGGREGATE_INVALID")?;
    let mut by_key = BTreeMap::<String, Vec<Value>>::new();
    for item in signatures {
        let public_key = item["signer_public_key"]
            .as_str()
            .ok_or("TN10_NATIVE_AGGREGATE_INVALID")?;
        let role = item["role"]
            .as_str()
            .ok_or("TN10_NATIVE_AGGREGATE_INVALID")?;
        by_key
            .entry(public_key.to_owned())
            .or_default()
            .push(serde_json::json!({
                "input_index":item["input_index"],
                "roles":[role],
                "signer_public_key":public_key,
                "sighash_type":item["sighash_type"],
                "sighash":item["sighash"],
                "signature":item["signature"]
            }));
    }
    let partials = by_key
        .into_iter()
        .map(|(public_key, signatures)| {
            serde_json::json!({
                "schema":"KTAPEOUT-TN10-NATIVE-PARTIAL-SIGNATURES-V1",
                "network":"testnet-10",
                "native_plan_hash":plan["plan_sha256"],
                "authorization_sha256":aggregate["authorization_sha256"],
                "signer_public_key":public_key,
                "signatures":signatures
            })
        })
        .collect::<Vec<_>>();
    let rebuilt = combine_native_registration_partials(plan, authorization, &partials, now_unix)?;
    if rebuilt["transaction"] != aggregate["transaction"]
        || rebuilt["signatures"] != aggregate["signatures"]
    {
        return Err("TN10_NATIVE_ASSEMBLED_TRANSACTION_MISMATCH".into());
    }
    Ok(rebuilt)
}

/// Explicit approval from the CLI, independent of every field in the plan.
pub fn confirm(
    plan: &Value,
    yes: bool,
    interactive: bool,
    input: impl io::BufRead,
    mut display: impl Write,
) -> Result<Value, Error> {
    let summary = signing_summary(plan)?;
    writeln!(display, "{}", serde_json::to_string_pretty(&summary)?)?;
    if yes {
        return Ok(summary);
    }
    if !interactive {
        return Err("TN10_CONFIRMATION_REQUIRED".into());
    }
    writeln!(display, "Type SIGN to approve exactly the operation above:")?;
    let mut answer = String::new();
    input.take(16).read_line(&mut answer)?;
    if answer.trim() != "SIGN" {
        return Err("TN10_CONFIRMATION_REQUIRED".into());
    }
    Ok(summary)
}

struct ErasingPair(Keypair);
impl Drop for ErasingPair {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

fn sign_material_before(
    plan: &Value,
    material: SecretMaterial,
    before_sign: impl FnOnce() -> Result<(), Error>,
) -> Result<Value, Error> {
    with_signing_material(plan, material, before_sign, |secp, message, pair| {
        secp.sign_schnorr_no_aux_rand(message, pair)
    })
}

fn with_signing_material(
    plan: &Value,
    material: SecretMaterial,
    before_sign: impl FnOnce() -> Result<(), Error>,
    sign: impl FnOnce(&Secp256k1<secp256k1::All>, &Message, &Keypair) -> secp256k1::schnorr::Signature,
) -> Result<Value, Error> {
    // Validate budgets and the frozen transaction before constructing any signing key.
    let summary = signing_summary(plan)?;
    let mut scalar =
        SecretKey::from_slice(material.0.as_ref()).map_err(|_| "TN10_SECRET_FORMAT_INVALID")?;
    let secp = Secp256k1::new();
    let pair = ErasingPair(Keypair::from_secret_key(&secp, &scalar));
    scalar.non_secure_erase();
    if hex::encode(pair.0.x_only_public_key().0.serialize()) != summary["signing_pubkey"] {
        return Err("TN10_SIGNING_KEY_MISMATCH".into());
    }
    let digest = hex::decode(
        summary["input_sighash_all"]
            .as_str()
            .ok_or("TN10_SIGHASH_MISSING")?,
    )?;
    let message = Message::from_digest_slice(&digest)?;
    before_sign()?;
    let signature = sign(&secp, &message, &pair.0);
    let mut bytes = signature.as_ref().to_vec();
    bytes.push(1); // Kaspa SIG_HASH_ALL, same format as detached signatures.
    attach_signature(plan, &hex::encode(bytes))
}

/// Conservative local accounting: attempted signatures are charged before computation.
/// A crash leaves the exclusive lock in place, requiring reconciliation instead of silent reuse.
struct BudgetGuard {
    path: std::path::PathBuf,
    lock: std::path::PathBuf,
    _held: File,
}
impl Drop for BudgetGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock);
    }
}
impl BudgetGuard {
    fn acquire(plan_path: &Path, plan: &mut Value) -> Result<Self, Error> {
        let summary = signing_summary(plan)?;
        let name = format!(
            ".tn10-budget-{}.json",
            summary["signing_pubkey"]
                .as_str()
                .ok_or("TN10_PLAN_INVALID")?
        );
        let path = plan_path.parent().unwrap_or(Path::new(".")).join(name);
        let lock = path.with_extension("lock");
        let held = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock)
            .map_err(|_| "TN10_BUDGET_LOCKED_RECONCILE_BEFORE_RETRY")?;
        let guard = Self {
            path,
            lock,
            _held: held,
        };
        if let Ok(meta) = fs::symlink_metadata(&guard.path) {
            if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > 4096 {
                return Err("TN10_BUDGET_STATE_INVALID".into());
            }
            let state: Value = serde_json::from_slice(&fs::read(&guard.path)?)?;
            if state["schema"] != "KTAPEOUT-TN10-SIGNING-BUDGET-V1"
                || state["signing_pubkey"] != summary["signing_pubkey"]
            {
                return Err("TN10_BUDGET_STATE_INVALID".into());
            }
            for field in ["spent_fee_sompi", "spent_value_sompi"] {
                let spent = state[field].as_u64().ok_or("TN10_BUDGET_STATE_INVALID")?;
                let declared = plan["request"]
                    .get(field)
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                plan["request"][field] = serde_json::json!(spent.max(declared));
            }
        }
        signing_summary(plan)?;
        Ok(guard)
    }
    fn reserve(&self, plan: &Value) -> Result<(), Error> {
        let summary = signing_summary(plan)?;
        let budget = &summary["budget"];
        let state = serde_json::json!({"schema":"KTAPEOUT-TN10-SIGNING-BUDGET-V1",
            "signing_pubkey":summary["signing_pubkey"],
            "spent_fee_sompi":budget["spent_fee_sompi"].as_u64().ok_or("TN10_BUDGET_STATE_INVALID")?
                .checked_add(summary["fee_sompi"].as_u64().ok_or("TN10_PLAN_INVALID")?).ok_or("TN10_CUMULATIVE_BUDGET_EXCEEDED")?,
            "spent_value_sompi":budget["spent_value_sompi"].as_u64().ok_or("TN10_BUDGET_STATE_INVALID")?
                .checked_add(summary["total_value_sompi"].as_u64().ok_or("TN10_PLAN_INVALID")?).ok_or("TN10_CUMULATIVE_BUDGET_EXCEEDED")?});
        let pending = self.path.with_extension("pending");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pending)
            .map_err(|_| "TN10_BUDGET_PENDING_RECONCILE_BEFORE_RETRY")?;
        file.write_all(&serde_json::to_vec_pretty(&state)?)?;
        file.sync_all()?;
        fs::rename(pending, &self.path)?;
        Ok(())
    }
}

/// Local signing and detached import share the same public confirmation and budget checks.
// The arguments are the CLI's mutually exclusive input choices and explicit approval.
#[allow(clippy::too_many_arguments)]
pub fn run(
    plan_path: &Path,
    authorization_path: Option<&Path>,
    output: &Path,
    key_path: Option<&Path>,
    key_stdin: bool,
    detached: Option<&Path>,
    yes: bool,
) -> Result<(), Error> {
    if usize::from(key_path.is_some()) + usize::from(key_stdin) + usize::from(detached.is_some())
        > 1
    {
        return Err("TN10_SIGN_INPUT_CONFLICT".into());
    }
    if output.exists() {
        return Err("TN10_SIGN_OUTPUT_EXISTS".into());
    }
    let document: Value = serde_json::from_slice(&fs::read(plan_path)?)?;
    let mut plan = document
        .get("native_transaction_plan")
        .filter(|value| value.is_object())
        .cloned()
        .unwrap_or(document);
    if matches!(
        plan["schema"].as_str(),
        Some("KTAPEOUT-TN10-NATIVE-CHILD-REGISTRATION-PLAN-V3")
            | Some("KTAPEOUT-TN10-NATIVE-OWNER-TARGET-PLAN-V1")
    ) {
        return run_native_registration(
            &plan,
            authorization_path.ok_or("TN10_NATIVE_AUTHORIZATION_REQUIRED")?,
            output,
            key_path,
            key_stdin,
            detached,
            yes,
        );
    }
    if authorization_path.is_some() {
        return Err("TN10_AUTHORIZATION_UNSUPPORTED_FOR_PLAN_VERSION".into());
    }
    let budget = BudgetGuard::acquire(plan_path, &mut plan)?;
    let terminal = io::stdin().is_terminal();
    confirm(&plan, yes, terminal, io::stdin().lock(), io::stderr())?;
    let signed = if let Some(path) = detached {
        let signature: Value = serde_json::from_slice(&fs::read(path)?)?;
        let result = import_signature(&plan, &signature)?;
        budget.reserve(&plan)?;
        result
    } else if let Some(path) = key_path {
        sign_material_before(&plan, SecretMaterial::file(path)?, || budget.reserve(&plan))?
    } else if key_stdin {
        let material = if terminal {
            interactive_secret()?
        } else {
            SecretMaterial::read(io::stdin().lock())?
        };
        sign_material_before(&plan, material, || budget.reserve(&plan))?
    } else if terminal {
        sign_material_before(&plan, interactive_secret()?, || budget.reserve(&plan))?
    } else {
        return Err("TN10_SECRET_INPUT_REQUIRED_USE_KEY_STDIN_OR_KEY_FILE".into());
    };
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    file.write_all(&serde_json::to_vec_pretty(&signed)?)?;
    file.sync_all()?;
    Ok(())
}

fn run_native_registration(
    plan: &Value,
    authorization_path: &Path,
    output: &Path,
    key_path: Option<&Path>,
    key_stdin: bool,
    detached: Option<&Path>,
    yes: bool,
) -> Result<(), Error> {
    if yes {
        return Err("TN10_NATIVE_SIGN_REQUIRES_TERMINAL_CONFIRMATION".into());
    }
    if detached.is_some() {
        return Err("TN10_NATIVE_DETACHED_SIGNATURE_UNSUPPORTED".into());
    }
    if !io::stdin().is_terminal() {
        return Err("TN10_NATIVE_SIGN_REQUIRES_TERMINAL_CONFIRMATION".into());
    }
    let authorization: Value = serde_json::from_slice(&fs::read(authorization_path)?)?;
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "TN10_CLOCK_INVALID")?
        .as_secs();
    crate::tn10_pipeline::verify_native_registration_authorization(plan, &authorization, now_unix)?;
    let requests = crate::tn10_pipeline::native_registration_signature_requests(plan)?;
    let material = if let Some(path) = key_path {
        SecretMaterial::file(path)?
    } else if key_stdin {
        SecretMaterial::read(io::stdin().lock())?
    } else {
        interactive_secret()?
    };
    let key_review = native_registration_key_review(plan, *material.0)?;
    if key_review["matching_roles"]
        .as_array()
        .is_none_or(|roles| roles.is_empty())
    {
        return Err("TN10_NATIVE_SIGNER_NOT_A_PLAN_ROLE".into());
    }
    let review = serde_json::json!({
        "network":plan["network"],
        "plan_sha256":plan["plan_sha256"],
        "role_public_keys":plan["role_public_keys"],
        "provided_key_review":key_review,
        "input_sighash_requests":requests["requests"],
        "cumulative_amount_limit_sompi":authorization["cumulative_amount_limit_sompi"],
        "fee_limit_sompi":authorization["fee_limit_sompi"],
        "authorization_expires_at_unix":authorization["expires_at_unix"],
        "broadcast":false
    });
    writeln!(io::stderr(), "{}", serde_json::to_string_pretty(&review)?)?;
    let expected = format!(
        "SIGN {}",
        plan["plan_sha256"].as_str().ok_or("TN10_PLAN_INVALID")?
    );
    writeln!(
        io::stderr(),
        "Type {expected} in this terminal to authorize this plan:"
    )?;
    let mut confirmation = String::new();
    io::stdin().lock().take(256).read_line(&mut confirmation)?;
    if confirmation.trim() != expected {
        return Err("TN10_NATIVE_SIGN_CONFIRMATION_REQUIRED".into());
    }
    let signed =
        sign_native_registration_partial(plan, &authorization, *material.0, now_unix, &expected)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|_| "TN10_SIGN_OUTPUT_EXISTS")?;
    file.write_all(&serde_json::to_vec_pretty(&signed)?)?;
    file.sync_all()?;
    Ok(())
}
