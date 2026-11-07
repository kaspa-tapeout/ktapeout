//! Discovery references are hashed presentation bytes, never executable runtime resources.
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const SCHEMA: &str = "KTAPEOUT-APPLICATION-DISCOVERY-V2";
fn invalid<T>() -> Result<T, String> {
    Err("DISCOVERY_V2_INVALID".into())
}
fn string<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v[k].as_str().ok_or_else(|| "DISCOVERY_V2_INVALID".into())
}
fn fields(v: &Value, required: &[&str], optional: &[&str]) -> bool {
    v.as_object().is_some_and(|o| {
        required.iter().all(|k| o.contains_key(*k))
            && o.keys()
                .all(|k| required.contains(&k.as_str()) || optional.contains(&k.as_str()))
    })
}
fn text(v: &Value, max: usize) -> bool {
    v.as_str().is_some_and(|s| {
        !s.trim().is_empty()
            && s.chars().count() <= max
            && !s
                .chars()
                .any(|c| c.is_ascii_control() || c == '\u{2028}' || c == '\u{2029}')
    })
}
fn hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn language(s: &str) -> bool {
    let parts: Vec<_> = s.split('-').collect();
    (1..=3).contains(&parts.len())
        && (2..=3).contains(&parts[0].len())
        && parts[0].bytes().all(|c| c.is_ascii_lowercase())
        && parts[1..]
            .iter()
            .all(|p| (2..=8).contains(&p.len()) && p.bytes().all(|c| c.is_ascii_alphanumeric()))
}
pub fn references(v: &Value) -> Vec<&Value> {
    v["locales"]
        .as_object()
        .into_iter()
        .flat_map(|o| o.values())
        .filter_map(|l| l.get("description"))
        .chain(v["media"].as_array().into_iter().flatten())
        .collect()
}
pub fn validate(
    v: &Value,
    network: &str,
    uri: &str,
    application_id: Option<&str>,
) -> Result<(), String> {
    if !fields(
        v,
        &[
            "schema",
            "network",
            "application_id",
            "canonical_uri",
            "default_language",
            "locales",
            "categories",
            "wallet",
            "media",
        ],
        &[],
    ) || v["schema"] != SCHEMA
        || v["network"] != network
        || v["canonical_uri"] != format!("ktape://{network}/app/{uri}")
        || !hash(string(v, "application_id")?)
        || application_id.is_some_and(|id| v["application_id"] != id)
    {
        return invalid();
    }
    let locales = v["locales"].as_object().ok_or("DISCOVERY_V2_INVALID")?;
    if locales.is_empty()
        || locales.len() > 8
        || !locales.contains_key(string(v, "default_language")?)
    {
        return invalid();
    }
    for (lang, locale) in locales {
        if !language(lang)
            || !fields(locale, &["name", "summary"], &["description"])
            || !text(&locale["name"], 128)
            || !text(&locale["summary"], 240)
        {
            return invalid();
        }
        if let Some(description) = locale.get("description") {
            if !fields(
                description,
                &["path", "sha256", "byte_length", "media_type"],
                &[],
            ) {
                return invalid();
            }
        }
    }
    let categories = v["categories"].as_array().ok_or("DISCOVERY_V2_INVALID")?;
    let mut seen = BTreeSet::new();
    if categories.is_empty() || categories.len() > 4 {
        return invalid();
    }
    for c in categories {
        let s = c.as_str().ok_or("DISCOVERY_V2_INVALID")?;
        if s.is_empty()
            || s.len() > 24
            || !s.as_bytes()[0].is_ascii_alphanumeric()
            || !s
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            || !seen.insert(s)
        {
            return invalid();
        }
    }
    if !["walletless", "wallet-optional", "user-signed"].contains(&string(v, "wallet")?) {
        return invalid();
    }
    let media = v["media"].as_array().ok_or("DISCOVERY_V2_INVALID")?;
    if media.len() > 10 {
        return invalid();
    }
    let mut roles = BTreeMap::new();
    let mut paths = BTreeMap::new();
    let mut total = 0;
    for r in references(v) {
        let image = r.get("role").is_some();
        let required = if image {
            vec![
                "path",
                "sha256",
                "byte_length",
                "media_type",
                "role",
                "width",
                "height",
                "alt",
            ]
        } else {
            vec!["path", "sha256", "byte_length", "media_type"]
        };
        if !fields(r, &required, &[]) {
            return invalid();
        }
        let p = string(r, "path")?;
        let digest = string(r, "sha256")?;
        let mime = string(r, "media_type")?;
        let size = r["byte_length"].as_u64().ok_or("DISCOVERY_V2_INVALID")?;
        if !p.starts_with("discovery/")
            || p == "discovery/metadata.json"
            || p.len() > 200
            || p.split('/').any(|s| s.is_empty() || s.starts_with('.'))
            || !p
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._/-".contains(&c))
            || !hash(digest)
            || size == 0
        {
            return invalid();
        }
        if image {
            let role = string(r, "role")?;
            let (limit, w, h, count) = match role {
                "icon" => (32768, 256, 256, 1),
                "card" => (153600, 1200, 630, 1),
                "banner" => (307200, 1920, 1080, 2),
                "screenshot" => (307200, 1920, 1080, 6),
                _ => return invalid(),
            };
            let n = roles.entry(role).or_insert(0);
            *n += 1;
            let width = r["width"].as_u64().ok_or("DISCOVERY_V2_INVALID")?;
            let height = r["height"].as_u64().ok_or("DISCOVERY_V2_INVALID")?;
            let suffix = match mime {
                "image/png" => p.ends_with(".png"),
                "image/webp" => p.ends_with(".webp"),
                "image/jpeg" => p.ends_with(".jpg") || p.ends_with(".jpeg"),
                _ => false,
            };
            let alt = r["alt"].as_object().ok_or("DISCOVERY_V2_INVALID")?;
            if *n > count
                || size > limit
                || width == 0
                || height == 0
                || width > w
                || height > h
                || !suffix
                || alt.len() != locales.len()
                || locales
                    .keys()
                    .any(|l| !alt.get(l).is_some_and(|v| text(v, 160)))
            {
                return invalid();
            }
        } else if mime != "text/markdown" || size > 65536 || !p.ends_with(".md") {
            return invalid();
        }
        let tuple = (digest, size, mime);
        if let Some(old) = paths.insert(p, tuple) {
            if old != tuple {
                return invalid();
            }
        } else {
            total += size;
        }
    }
    // Every media entry must actually be an image reference.
    if media.iter().any(|r| r.get("role").is_none())
        || total > 3 * 1024 * 1024
        || serde_json::to_vec(v)
            .map_err(|_| "DISCOVERY_V2_INVALID")?
            .len()
            > 16384
    {
        return invalid();
    }
    Ok(())
}
pub fn markdown(bytes: &[u8]) -> Result<(), String> {
    let s = std::str::from_utf8(bytes).map_err(|_| "DISCOVERY_MARKDOWN_INVALID")?;
    if bytes.len() > 65536
        || s.contains(['<', '>'])
        || s.contains("![")
        || s.contains("][")
        || s.chars()
            .any(|c| c.is_control() && !['\n', '\r', '\t'].contains(&c))
    {
        return Err("DISCOVERY_MARKDOWN_INVALID".into());
    }
    for line in s.lines() {
        if line.trim_start().starts_with('[') && line.contains("]:") {
            return Err("DISCOVERY_MARKDOWN_INVALID".into());
        }
    }
    for part in s.split("](").skip(1) {
        if let Some((url, _)) = part.split_once(')') {
            let host = url
                .strip_prefix("https://")
                .and_then(|s| s.split(['/', '?', '#']).next())
                .unwrap_or("");
            if host.is_empty() || host.contains('@') || url.contains(['\\', ' ', '\n', '\r', '\t'])
            {
                return Err("DISCOVERY_MARKDOWN_LINK_INVALID".into());
            }
        }
    }
    Ok(())
}
pub fn verify(r: &Value, bytes: &[u8]) -> Result<(), String> {
    if r["byte_length"].as_u64() != Some(bytes.len() as u64)
        || r["sha256"] != hex::encode(Sha256::digest(bytes))
    {
        return Err("DISCOVERY_REFERENCE_HASH_MISMATCH".into());
    }
    if r["media_type"] == "text/markdown" {
        return markdown(bytes);
    }
    let dimensions =
        dimensions(bytes, string(r, "media_type")?).ok_or("DISCOVERY_MEDIA_DIMENSIONS_INVALID")?;
    if r["width"].as_u64() != Some(dimensions.0 as u64)
        || r["height"].as_u64() != Some(dimensions.1 as u64)
    {
        return Err("DISCOVERY_MEDIA_DIMENSIONS_MISMATCH".into());
    }
    Ok(())
}
fn dimensions(b: &[u8], mime: &str) -> Option<(u32, u32)> {
    let be =
        |p: usize| -> Option<u32> { Some(u32::from_be_bytes(b.get(p..p + 4)?.try_into().ok()?)) };
    let le =
        |p: usize| -> Option<u32> { Some(u32::from_le_bytes(b.get(p..p + 4)?.try_into().ok()?)) };
    if mime == "image/png" && b.starts_with(b"\x89PNG\r\n\x1a\n") && b.get(12..16)? == b"IHDR" {
        let mut p = 8;
        while p < b.len() {
            let n = be(p)? as usize;
            let tag = b.get(p + 4..p + 8)?;
            if [b"acTL", b"fcTL", b"fdAT"].contains(&tag.try_into().ok()?) {
                return None;
            }
            p = p.checked_add(n + 12)?;
            if p > b.len() {
                return None;
            }
        }
        return Some((be(16)?, be(20)?));
    }
    if mime == "image/webp"
        && b.get(0..4)? == b"RIFF"
        && b.get(8..12)? == b"WEBP"
        && le(4)? as usize + 8 == b.len()
    {
        let mut p = 12;
        let mut result = None;
        while p + 8 <= b.len() {
            let tag = b.get(p..p + 4)?;
            let n = le(p + 4)? as usize;
            let q = p + 8;
            if q + n > b.len() {
                return None;
            }
            if tag == b"ANIM" || tag == b"ANMF" {
                return None;
            }
            if tag == b"VP8X" && n >= 10 {
                if b[q] & 2 != 0 {
                    return None;
                }
                let u = |p: usize| {
                    b[p] as u32 + ((b[p + 1] as u32) << 8) + ((b[p + 2] as u32) << 16) + 1
                };
                result = Some((u(q + 4), u(q + 7)));
            }
            if tag == b"VP8 " && n >= 10 && b.get(q + 3..q + 6)? == [0x9d, 1, 0x2a] {
                result = Some((
                    u16::from_le_bytes(b[q + 6..q + 8].try_into().ok()?) as u32 & 16383,
                    u16::from_le_bytes(b[q + 8..q + 10].try_into().ok()?) as u32 & 16383,
                ));
            }
            if tag == b"VP8L" && n >= 5 && b[q] == 0x2f {
                let bits = le(q + 1)?;
                result = Some(((bits & 16383) + 1, ((bits >> 14) & 16383) + 1));
            }
            p = q + n + n % 2;
        }
        return result;
    }
    if mime == "image/jpeg" && b.starts_with(&[255, 216, 255]) {
        let mut p = 2;
        while p + 4 <= b.len() {
            if b[p] != 255 {
                return None;
            }
            p += 1;
            while b.get(p) == Some(&255) {
                p += 1;
            }
            let tag = *b.get(p)?;
            p += 1;
            if tag == 0xd9 || tag == 0xda {
                break;
            }
            let n = u16::from_be_bytes(b.get(p..p + 2)?.try_into().ok()?) as usize;
            if n < 2 || p + n > b.len() {
                return None;
            }
            if [0xc0, 0xc1, 0xc2].contains(&tag) && n >= 8 {
                return Some((
                    u16::from_be_bytes(b[p + 5..p + 7].try_into().ok()?) as u32,
                    u16::from_be_bytes(b[p + 3..p + 5].try_into().ok()?) as u32,
                ));
            }
            p += n;
        }
    }
    None
}
