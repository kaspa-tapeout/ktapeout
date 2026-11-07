//! Read-only site checks scoped to one application. Host inventory drift is diagnostic;
//! the requested application's resource closure must match its pinned route exactly.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const PRIVATE_KEY_MARKERS: [&str; 5] = [
    concat!("-----BEGIN ", "PRIVATE KEY-----"),
    concat!("-----BEGIN ENCRYPTED ", "PRIVATE KEY-----"),
    concat!("-----BEGIN RSA ", "PRIVATE KEY-----"),
    concat!("-----BEGIN EC ", "PRIVATE KEY-----"),
    concat!("-----BEGIN OPENSSH ", "PRIVATE KEY-----"),
];

fn error(code: &str, path: &str) -> String {
    format!("SITE_CHECK:{code}:{path}")
}

fn relative(value: &str) -> Result<&str, String> {
    if value.is_empty()
        || value.starts_with('/')
        || value.contains('\\')
        || value.contains(':')
        || value
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
    {
        return Err(error("UNSAFE_PATH", value));
    }
    Ok(value)
}

fn resolve(root: &Path, value: &str) -> Result<PathBuf, String> {
    let mut path = root.to_path_buf();
    for part in relative(value)?.split('/') {
        path.push(part);
        match fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_symlink() => return Err(error("SYMLINK_FORBIDDEN", value)),
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(error("FILE_UNAVAILABLE", value)),
        }
    }
    Ok(path)
}

fn read(root: &Path, value: &str) -> Result<Vec<u8>, String> {
    let p = resolve(root, value)?;
    let size = fs::metadata(&p)
        .map_err(|_| error("FILE_UNAVAILABLE", value))?
        .len();
    if size > 32 * 1024 * 1024 {
        return Err(error("FILE_TOO_LARGE", value));
    }
    let bytes = fs::read(p).map_err(|_| error("FILE_UNAVAILABLE", value))?;
    let head = bytes
        .strip_prefix(&[0xef, 0xbb, 0xbf])
        .unwrap_or(&bytes)
        .trim_ascii_start();
    if PRIVATE_KEY_MARKERS
        .iter()
        .any(|marker| head.starts_with(marker.as_bytes()))
    {
        return Err(error("SECRET_CONTENT_FORBIDDEN", value));
    }
    Ok(bytes)
}

fn json_file(root: &Path, value: &str) -> Result<Value, String> {
    let bytes = read(root, value)?;
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes);
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(error("JSON_TOO_LARGE", value));
    }
    ktapeout_runtime::parse_strict_json(bytes).map_err(|_| error("JSON_INVALID", value))
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn string<'a>(v: &'a Value, field: &str) -> Result<&'a str, String> {
    v[field]
        .as_str()
        .ok_or_else(|| error("FIELD_INVALID", field))
}

fn route_path<'a>(route: &'a Value, field: &str) -> Result<&'a str, String> {
    let p = string(route, field)?;
    p.strip_prefix('/')
        .ok_or_else(|| error("ROUTE_PATH_INVALID", p))
        .and_then(relative)
}

fn closure(root: &Path, route: &Value) -> Result<Value, String> {
    let manifest_path = route_path(route, "manifest")?;
    let manifest_bytes = read(root, manifest_path)?;
    if digest(&manifest_bytes) != string(route, "manifest_sha256")? {
        return Err(error("MANIFEST_HASH_MISMATCH", manifest_path));
    }
    let m = json_file(root, manifest_path)?;
    let uri = format!(
        "ktape://{}/app/{}",
        string(route, "network")?,
        string(route, "application_uri")?
    );
    if m["schema"] != "KTAPEOUT-STATIC-RUNTIME-MANIFEST-V1"
        || m["network"] != route["network"]
        || m["release_id"] != route["release_id"]
        || m["application_uri"] != uri
        || m["entrypoint"] != route["entrypoint"]
    {
        return Err(error("MANIFEST_BINDING_MISMATCH", manifest_path));
    }
    let parent = manifest_path.rsplit_once('/').map(|p| p.0).unwrap_or("");
    let files = m["files"]
        .as_array()
        .ok_or_else(|| error("RESOURCE_TABLE_INVALID", manifest_path))?;
    if files.is_empty() || files.len() > 512 {
        return Err(error("RESOURCE_TABLE_INVALID", manifest_path));
    }
    let mut paths = BTreeSet::new();
    let mut total = 0u64;
    for file in files {
        let rel = relative(string(file, "path")?)?;
        if !paths.insert(rel) {
            return Err(error("DUPLICATE_RESOURCE", rel));
        }
        let full = if parent.is_empty() {
            rel.into()
        } else {
            format!("{parent}/{rel}")
        };
        let b = read(root, &full)?;
        if file["byte_length"].as_u64() != Some(b.len() as u64)
            || string(file, "sha256")? != digest(&b)
        {
            return Err(error("RESOURCE_HASH_MISMATCH", &full));
        }
        total += b.len() as u64;
        if total > 64 * 1024 * 1024 {
            return Err(error("RESOURCE_TOTAL_TOO_LARGE", manifest_path));
        }
    }
    let entrypoint = route_path(route, "entrypoint")?;
    let entry_rel = entrypoint
        .strip_prefix(&format!("{parent}/"))
        .ok_or_else(|| error("ENTRYPOINT_OUTSIDE_CLOSURE", entrypoint))?;
    if !paths.contains(entry_rel) {
        return Err(error("ENTRYPOINT_NOT_LISTED", entrypoint));
    }
    let commitment = verify_commitment(root, parent, &m, files, entry_rel)?;
    if route.get("content_locator").is_some() {
        let p = route_path(route, "content_locator")?;
        if digest(&read(root, p)?) != string(route, "content_locator_sha256")? {
            return Err(error("LOCATOR_HASH_MISMATCH", p));
        }
        let locator = json_file(root, p)?;
        for field in [
            "network",
            "application_uri",
            "release_id",
            "package_digest",
            "entrypoint",
        ] {
            if locator.get(field).is_none() || locator[field] != m[field] {
                return Err(error("LOCATOR_BINDING_MISMATCH", p));
            }
        }
        if locator["schema"] != "KTAPEOUT-BROWSER-CONTENT-LOCATOR-V1"
            || locator["files"] != m["files"]
        {
            // Locator resources additionally carry transport fields; compare their identity projection.
            let rows = locator["files"]
                .as_array()
                .ok_or_else(|| error("LOCATOR_RESOURCES_INVALID", p))?;
            if locator["schema"] != "KTAPEOUT-BROWSER-CONTENT-LOCATOR-V1"
                || rows.len() != files.len()
            {
                return Err(error("LOCATOR_RESOURCES_INVALID", p));
            }
            let mut seen = BTreeSet::new();
            for row in rows {
                let name = string(row, "path")?;
                if !seen.insert(name) {
                    return Err(error("DUPLICATE_LOCATOR_RESOURCE", name));
                }
                let resource = files
                    .iter()
                    .find(|f| f["path"] == row["path"])
                    .ok_or_else(|| error("LOCATOR_RESOURCE_UNKNOWN", name))?;
                for field in ["sha256", "byte_length", "media_type"] {
                    if row[field] != resource[field] {
                        return Err(error("LOCATOR_RESOURCE_MISMATCH", name));
                    }
                }
            }
        }
    }
    Ok(
        json!({"files":files.len(),"bytes":total,"manifest_sha256":digest(&manifest_bytes),"content_commitment":commitment}),
    )
}

fn verify_commitment(
    root: &Path,
    parent: &str,
    manifest: &Value,
    files: &[Value],
    entry: &str,
) -> Result<Value, String> {
    let Some(c) = manifest.get("content_commitment") else {
        return Ok(json!({"status":"NOT_DECLARED"}));
    };
    let invalid = || error("CONTENT_COMMITMENT_INVALID", parent);
    let object = c.as_object().ok_or_else(invalid)?;
    if object.len() != 4 || c["schema"] != "KTAPEOUT-RUNTIME-CONTENT-COMMITMENT-V1" {
        return Err(invalid());
    }
    let path = relative(string(c, "manifest_path")?)?;
    let expected_root = string(c, "artifact_root")?;
    if expected_root.len() != 64
        || !expected_root
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    if !files.iter().any(|f| f["path"] == path) {
        return Err(invalid());
    }
    let full = if parent.is_empty() {
        path.to_string()
    } else {
        format!("{parent}/{path}")
    };
    let bytes = read(root, &full)?;
    let declared = json_file(root, &full)?;
    let directory = path
        .rsplit_once('/')
        .map(|p| format!("{}/", p.0))
        .unwrap_or_default();
    let mut covered = BTreeSet::new();
    let adapter = string(c, "adapter_id")?;
    let rows = match adapter {
        "sha256-canonical-chunks-v1" => {
            let schema = string(&declared, "schema")?;
            if bytes.len() > 65536
                || schema.is_empty()
                || schema.len() > 128
                || declared["network"] != manifest["network"]
                || declared["root_scheme"] != adapter
                || declared["content_root"] != expected_root
                || declared
                    .get("release_id")
                    .is_some_and(|id| id != &manifest["release_id"])
            {
                return Err(invalid());
            }
            declared["chunks"].as_array().ok_or_else(invalid)?
        }
        "OnChainContentV1" => {
            ktapeout_core::verify_content_artifact_050(&bytes).map_err(|_| invalid())?;
            if declared["artifact_sha256"] != expected_root
                || format!("{directory}{}", string(&declared, "entrypoint")?) != entry
            {
                return Err(invalid());
            }
            declared["files"].as_array().ok_or_else(invalid)?
        }
        _ => return Err(error("CONTENT_COMMITMENT_ADAPTER_UNAUTHORIZED", adapter)),
    };
    if rows.is_empty() || rows.len() > 512 {
        return Err(invalid());
    }
    // Struct serialization preserves the protocol's path-then-sha256 key order.
    #[derive(serde::Serialize)]
    struct Leaf<'a> {
        path: &'a str,
        sha256: &'a str,
    }
    let mut leaves = Vec::new();
    for row in rows {
        let name = relative(string(row, "path")?)?;
        let resource_path = format!("{directory}{name}");
        if resource_path == path || !covered.insert(resource_path.clone()) {
            return Err(invalid());
        }
        let resource = files
            .iter()
            .find(|f| f["path"] == resource_path)
            .ok_or_else(invalid)?;
        if row["sha256"] != resource["sha256"]
            || (adapter == "OnChainContentV1" && row["size"] != resource["byte_length"])
        {
            return Err(error("CONTENT_COMMITMENT_CHUNK_MISMATCH", name));
        }
        leaves.push(Leaf {
            path: name,
            sha256: string(row, "sha256")?,
        });
    }
    if adapter == "sha256-canonical-chunks-v1"
        && digest(&serde_json::to_vec(&leaves).map_err(|_| invalid())?) != expected_root
    {
        return Err(error("CONTENT_COMMITMENT_ROOT_MISMATCH", path));
    }
    if files
        .iter()
        .any(|f| f["path"] != path && !covered.contains(f["path"].as_str().unwrap_or("")))
    {
        return Err(error("CONTENT_COMMITMENT_COVERAGE_INCOMPLETE", path));
    }
    Ok(json!({"status":"VERIFIED","artifact_root":expected_root,"adapter_id":adapter}))
}

pub fn check(root: &Path, application_uri: &str) -> Result<Value, String> {
    let root = root
        .canonicalize()
        .map_err(|_| error("ROOT_UNAVAILABLE", "root"))?;
    let suffix = application_uri
        .strip_prefix("ktape://")
        .ok_or_else(|| error("APPLICATION_URI_INVALID", application_uri))?;
    let (network, slug) = suffix
        .split_once("/app/")
        .ok_or_else(|| error("APPLICATION_URI_INVALID", application_uri))?;
    relative(network)?;
    relative(slug)?;
    if network.contains('/') || slug.split('/').count() != 2 {
        return Err(error("APPLICATION_URI_INVALID", application_uri));
    }
    let routing = json_file(&root, "assets/application-runtime-routing.json")?;
    if routing["schema"] != "KTAPEOUT-APPLICATION-RUNTIME-ROUTING-V1" {
        return Err(error("ROUTING_SCHEMA_INVALID", "routing"));
    }
    let routes = routing["routes"]
        .as_array()
        .ok_or_else(|| error("ROUTES_INVALID", "routing"))?;
    if routes.len() > 128 {
        return Err(error("ROUTES_TOO_MANY", "routing"));
    }
    let targets: Vec<_> = routes
        .iter()
        .filter(|r| r["network"] == network && r["application_uri"] == slug)
        .collect();
    if targets.len() != 1 {
        return Err(error("TARGET_ROUTE_NOT_UNIQUE", application_uri));
    }
    let target = targets[0];
    let target_check = closure(&root, target)?;
    let mut warnings = Vec::new();
    for route in routes
        .iter()
        .filter(|r| !(r["network"] == network && r["application_uri"] == slug))
    {
        if let Err(code) = closure(&root, route) {
            warnings.push(json!({"scope":"OTHER_APPLICATION","application_uri":route["application_uri"],"error":code}));
        }
    }
    let inventory = json_file(&root, "KTAPEOUT_PAGES_ARTIFACT.json")?;
    if inventory["schema"] != "KTAPEOUT-PAGES-ARTIFACT-V1" {
        return Err(error("INVENTORY_SCHEMA_INVALID", "inventory"));
    }
    let entries = inventory["files"]
        .as_array()
        .ok_or_else(|| error("INVENTORY_INVALID", "inventory"))?;
    if entries.len() > 10000 {
        return Err(error("INVENTORY_TOO_LARGE", "inventory"));
    }
    let mut seen = BTreeSet::new();
    let mut inventory_bytes = 0u64;
    for entry in entries {
        let p = relative(string(entry, "path")?)?;
        if !seen.insert(p) {
            return Err(error("INVENTORY_DUPLICATE", p));
        }
        if let Ok(metadata) = fs::metadata(resolve(&root, p)?) {
            inventory_bytes = inventory_bytes.saturating_add(metadata.len());
            if inventory_bytes > 512 * 1024 * 1024 {
                return Err(error("INVENTORY_TOTAL_TOO_LARGE", "inventory"));
            }
        }
        // Public modules named private-*.js are ordinary source files. Actual key containers are forbidden.
        let name = p.rsplit('/').next().unwrap_or(p).to_ascii_lowercase();
        if name == ".env"
            || name.starts_with(".env.")
            || name.ends_with("private.pem")
            || name.ends_with(".key")
            || name.ends_with(".p12")
            || name.ends_with(".pfx")
            || ["seed.json", "mnemonic.json", "wallet.json"].contains(&name.as_str())
        {
            return Err(error("SECRET_FILE_FORBIDDEN", p));
        }
        let issue = match read(&root, p) {
            Ok(b)
                if Some(b.len() as u64) == entry["bytes"].as_u64()
                    && digest(&b) == string(entry, "sha256")? =>
            {
                None
            }
            Ok(_) => Some("INVENTORY_HASH_MISMATCH"),
            Err(code) if code.starts_with("SITE_CHECK:SECRET_CONTENT_FORBIDDEN:") => {
                return Err(code)
            }
            Err(_) => Some("INVENTORY_MEMBER_UNAVAILABLE"),
        };
        if let Some(code) = issue {
            warnings.push(json!({"scope":"SITE_INVENTORY","path":p,"error":code}));
        }
    }
    Ok(
        json!({"schema":"KTAPEOUT-SITE-CHECK-V1","status":"TARGET_RESOURCE_CLOSURE_VERIFIED",
        "application_uri":application_uri,"release_id":target["release_id"],"target":target_check,"warnings":warnings,
        "scope":"Local file, locator and declared content commitment verification; does not authenticate publisher signatures, L1 state, TLS, Host adapter admission or deployment authority.",
        "signing_allowed":false,"broadcast":false,"deployment":false}),
    )
}
