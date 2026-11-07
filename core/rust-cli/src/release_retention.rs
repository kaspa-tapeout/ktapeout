//! Retention check for a release: every file must be obtainable, byte-for-byte, from at least two independent
//! content-addressed sources (`{source}/sha256/{digest}`) before the release may be called retained. A pinned,
//! environment-less helper only fetches; this module re-hashes every byte itself. A single source or a source missing
//! any file never counts, and a temporary TN10 demo has to be declared, never inferred.
use crate::release_closure::sha256;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::Path;

pub struct Helper<'a> {
    pub path: &'a Path,
    pub sha256: &'a str,
}

/// Host of an https source URL, lowercase, without port; independent means a distinct host.
fn host(source: &str) -> Result<String, String> {
    let rest = source
        .strip_prefix("https://")
        .ok_or("RETENTION_SOURCE_MUST_BE_HTTPS")?;
    let authority = rest.split('/').next().unwrap_or_default();
    let host = authority
        .rsplit_once(':')
        .map_or(authority, |(h, _)| h)
        .to_ascii_lowercase();
    if host.is_empty() || authority.contains('@') || rest.contains('?') || rest.contains('#') {
        return Err("RETENTION_SOURCE_MUST_BE_PLAIN_HTTPS".into());
    }
    Ok(host)
}

/// Verdict from per-source verification results. `verified[source]` is the set of file digests whose bytes matched.
pub fn assess(
    sources: &[String],
    files: &[(String, u64)],
    verified: &[BTreeSet<String>],
    declared_temporary: bool,
) -> Result<Value, String> {
    if sources.len() != verified.len() {
        return Err("RETENTION_RESULT_SHAPE_INVALID".into());
    }
    let wanted: BTreeSet<&String> = files.iter().map(|(d, _)| d).collect();
    let mut complete_hosts = BTreeSet::new();
    let mut per_source = Vec::new();
    for (source, got) in sources.iter().zip(verified) {
        let complete = wanted.iter().all(|d| got.contains(*d));
        let source_host = host(source)?;
        if complete {
            complete_hosts.insert(source_host);
        }
        per_source.push(json!({"source": source, "verified_files": got.len(), "required_files": wanted.len(), "complete": complete}));
    }
    let independent = complete_hosts.len();
    let status = match (independent, declared_temporary) {
        (n, _) if n >= 2 => "RETAINED_BY_INDEPENDENT_SOURCES",
        (n, true) if n >= 1 => "TEMPORARY_DECLARED",
        _ => "NOT_RETAINED",
    };
    Ok(
        json!({"schema": "KTAPEOUT-RETENTION-CHECK-V1", "status": status, "independent_complete_sources": independent,
        "required_independent_sources": 2, "sources": per_source, "signing_allowed": false, "broadcast": false}),
    )
}

/// Run the cold reader and re-hash everything it wrote. Files are `(sha256, byte_length)`.
pub fn cold_read(
    helper: &Helper,
    sources: &[String],
    files: &[(String, u64)],
    declared_temporary: bool,
) -> Result<Value, String> {
    use std::process::{Command, Stdio};
    if sources.is_empty() || sources.len() > 8 || files.is_empty() || files.len() > 129 {
        return Err("RETENTION_REQUEST_INVALID".into());
    }
    for source in sources {
        host(source)?;
    }
    let bytes = std::fs::read(helper.path).map_err(|_| "RETENTION_HELPER_UNAVAILABLE")?;
    if sha256(&bytes) != helper.sha256 {
        return Err("RETENTION_HELPER_CHANGED".into());
    }
    let dir = std::env::temp_dir().join(format!(
        "ktape-retention-{}-{}",
        std::process::id(),
        &helper.sha256[..8]
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|_| "RETENTION_WORKDIR_UNAVAILABLE")?;
    let request = dir.join("request.json");
    let out = dir.join("out");
    let rows: Vec<Value> = files
        .iter()
        .map(|(d, n)| json!({"sha256": d, "byte_length": n}))
        .collect();
    std::fs::write(
        &request,
        json!({"sources": sources, "files": rows}).to_string(),
    )
    .map_err(|_| "RETENTION_WORKDIR_UNAVAILABLE")?;
    let mut child = Command::new(helper.path)
        .arg(&request)
        .arg(&out)
        .env_clear()
        .envs(
            ["SystemRoot", "windir"]
                .iter()
                .filter_map(|k| std::env::var(k).ok().map(|v| (*k, v))),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "RETENTION_HELPER_SPAWN_FAILED")?;
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| "RETENTION_HELPER_WAIT_FAILED")?
        {
            break status;
        }
        if started.elapsed().as_secs() > 60 * (sources.len() as u64) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(&dir);
            return Err("RETENTION_HELPER_TIMEOUT".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    if !status.success() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err("RETENTION_HELPER_FAILED".into());
    }
    let mut verified = Vec::new();
    for index in 0..sources.len() {
        let mut got = BTreeSet::new();
        for (digest, length) in files {
            let path = out.join(index.to_string()).join(digest);
            if let Ok(data) = std::fs::read(&path) {
                if data.len() as u64 == *length && &sha256(&data) == digest {
                    got.insert(digest.clone());
                }
            }
        }
        verified.push(got);
    }
    let _ = std::fs::remove_dir_all(&dir);
    assess(sources, files, &verified, declared_temporary)
}
