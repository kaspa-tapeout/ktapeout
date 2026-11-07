use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const CATEGORIES: &[&str] = &[
    "protocol",
    "infrastructure",
    "finance",
    "commerce",
    "marketplace",
    "game",
    "social",
    "content",
    "identity",
    "productivity",
    "developer",
    "science",
    "education",
    "simulation",
    "utility",
    "other",
];
const TAGS: &[&str] = &[
    "walletless",
    "wallet-optional",
    "user-signed",
    "operator-settlement",
    "non-custodial",
    "escrow",
    "payments",
    "trading",
    "prediction",
    "subscription",
    "multiplayer",
    "open-data",
    "scientific",
    "educational",
    "developer-tool",
];
const SURFACES: &[&str] = &["web", "pwa", "cli", "browser-extension", "studio", "api"];
const FIELDS: &[&str] = &[
    "schema",
    "protocol_semver",
    "network",
    "application_id",
    "canonical_uri",
    "category_schema",
    "display_name",
    "primary_category",
    "secondary_categories",
    "tags",
    "surfaces",
    "status",
    "owner_authority",
    "metadata_revision",
    "previous_metadata_hash",
    "effective_at",
    "metadata_id",
];

fn invalid(message: &str) -> String {
    message.to_owned()
}

fn text<'a>(value: &'a Value, field: &str, maximum: usize) -> Result<&'a str, String> {
    let value = value
        .as_str()
        .ok_or_else(|| invalid(&format!("{field} is invalid")))?;
    if value.trim().is_empty()
        || value.chars().count() > maximum
        || value.chars().any(forbidden_control)
    {
        return Err(invalid(&format!("{field} is invalid")));
    }
    Ok(value)
}

fn forbidden_control(value: char) -> bool {
    value.is_control() || matches!(value, '\u{2028}' | '\u{2029}')
}

fn hash64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical(value: &Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value)
        .map_err(|error| format!("discovery metadata JSON is invalid: {error}"))
}

fn metadata_digest(value: &Value) -> Result<String, String> {
    let bytes = canonical(value)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn python_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|number| number != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn python_string(value: &Value) -> String {
    match value {
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        _ => value.to_string(),
    }
}

fn uri_valid(uri: &str, network: &str) -> bool {
    let Some(path) = uri.strip_prefix(&format!("ktape://{network}/app/")) else {
        return false;
    };
    let mut parts = path.split('/');
    let Some(namespace) = parts.next() else {
        return false;
    };
    let Some(mut slug) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    if let Some((name, release)) = slug.split_once('@') {
        if !hash64(release) || name.contains('@') {
            return false;
        }
        slug = name;
    }
    slug_full(namespace) && slug_full(slug)
}

fn slug_full(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

pub fn catalog() -> Value {
    json!({
        "schema":"KTAPEOUT-APPLICATION-CATEGORY-CATALOG-V1",
        "version":"1.0.0",
        "primary_categories":CATEGORIES,
        "controlled_tags":TAGS,
        "access_surfaces":SURFACES,
        "limits":{"secondary_categories_max":3,"tags_max":8,"surfaces_max":4},
        "reserved_non_categories":["web","pwa","cli","browser-extension","studio","api"]
    })
}

pub fn validate(value: &Value, expected_network: Option<&str>) -> Result<Value, String> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("discovery metadata schema is invalid"))?;
    if object.get("schema").and_then(Value::as_str)
        != Some("KTAPEOUT-APPLICATION-DISCOVERY-METADATA-V1")
    {
        return Err(invalid("discovery metadata schema is invalid"));
    }
    if object.len() != FIELDS.len() || FIELDS.iter().any(|field| !object.contains_key(*field)) {
        return Err(invalid("discovery metadata fields are not canonical"));
    }
    let network = object["network"].as_str().unwrap_or_default();
    if !matches!(network, "testnet-10" | "mainnet")
        || expected_network.is_some_and(|expected| network != expected)
    {
        return Err(invalid("discovery metadata network is invalid"));
    }
    for field in ["metadata_id", "application_id"] {
        if !object[field].as_str().is_some_and(hash64) {
            return Err(invalid(&format!("{field} must be canonical sha256")));
        }
    }
    if object["protocol_semver"] != "0.5.0"
        || object["category_schema"] != "KTAPEOUT-APPLICATION-CATEGORY-V1"
    {
        return Err(invalid(
            "discovery metadata protocol or catalog version is invalid",
        ));
    }
    if !object["canonical_uri"]
        .as_str()
        .is_some_and(|uri| uri_valid(uri, network))
    {
        return Err(invalid("canonical_uri is invalid or network-mismatched"));
    }
    let owner = object["owner_authority"].as_str().unwrap_or_default();
    if !(8..=256).contains(&owner.chars().count()) || owner.chars().any(forbidden_control) {
        return Err(invalid("owner_authority is invalid"));
    }
    text(&object["effective_at"], "effective_at", 64)?;
    if !object["previous_metadata_hash"].is_null()
        && !object["previous_metadata_hash"]
            .as_str()
            .is_some_and(hash64)
    {
        return Err(invalid("previous_metadata_hash is invalid"));
    }
    text(&object["display_name"], "display_name", 128)?;
    let primary = object["primary_category"].as_str().unwrap_or_default();
    if !CATEGORIES.contains(&primary) || SURFACES.contains(&primary) {
        return Err(invalid("primary_category is not in the controlled catalog"));
    }
    validate_string_list(
        &object["secondary_categories"],
        CATEGORIES,
        3,
        Some(primary),
    )
    .map_err(|_| invalid("secondary_categories is invalid"))?;
    validate_string_list(&object["tags"], TAGS, 8, None)
        .map_err(|_| invalid("tags are invalid"))?;
    validate_string_list(&object["surfaces"], SURFACES, 4, None)
        .map_err(|_| invalid("surfaces are invalid"))?;
    if object["surfaces"].as_array().is_none_or(Vec::is_empty) {
        return Err(invalid("surfaces are invalid"));
    }
    let status = object["status"].as_str().unwrap_or_default();
    if ![
        "UNCLASSIFIED",
        "DECLARED",
        "CATALOG_VALIDATED",
        "L1_BOUND",
        "DEPRECATED",
    ]
    .contains(&status)
        || object["metadata_revision"]
            .as_i64()
            .is_none_or(|revision| !(1..=i32::MAX as i64).contains(&revision))
    {
        return Err(invalid("discovery metadata status or revision is invalid"));
    }
    if canonical(value)?.len() > 8 * 1024 {
        return Err(invalid("discovery metadata exceeds 8 KiB"));
    }
    Ok(value.clone())
}

fn validate_string_list(
    value: &Value,
    allowed: &[&str],
    maximum: usize,
    excluded: Option<&str>,
) -> Result<(), ()> {
    let list = value.as_array().ok_or(())?;
    if list.len() > maximum {
        return Err(());
    }
    let mut seen = std::collections::BTreeSet::new();
    for item in list {
        let text = item.as_str().ok_or(())?;
        if !allowed.contains(&text) || excluded == Some(text) || !seen.insert(text) {
            return Err(());
        }
    }
    Ok(())
}

pub fn hash(value: &Value) -> Result<String, String> {
    let validated = validate(value, None)?;
    let mut hasher = Sha256::new();
    hasher.update(b"KTAPEOUT/0.5.0/DISCOVERY-METADATA/V1\0");
    hasher.update(canonical(&validated)?);
    Ok(hex::encode(hasher.finalize()))
}

pub fn migrate(application: &Value, network: &str) -> Result<Value, String> {
    let application_id = application
        .get("application_id")
        .and_then(Value::as_str)
        .filter(|value| hash64(value))
        .ok_or_else(|| invalid("application record is invalid"))?;
    if !matches!(network, "testnet-10" | "mainnet") {
        return Err(invalid("discovery metadata network is invalid"));
    }
    let display_name = application
        .get("display_name")
        .map(python_string)
        .unwrap_or_else(|| "Unclassified application".to_owned())
        .chars()
        .take(128)
        .collect::<String>();
    let display_name = if display_name.is_empty() {
        "Unclassified application".to_owned()
    } else {
        display_name
    };
    let fallback_uri = || {
        format!(
            "ktape://{network}/app/unclassified/{}",
            &application_id[..12]
        )
    };
    let canonical_uri = application
        .get("canonical_uri")
        .filter(|value| python_truthy(value))
        .cloned()
        .unwrap_or_else(|| Value::String(fallback_uri()));
    let owner = application
        .get("authority")
        .map(python_string)
        .unwrap_or_else(|| "unassigned-authority".to_owned());
    let mut body = json!({
        "schema":"KTAPEOUT-APPLICATION-DISCOVERY-METADATA-V1",
        "protocol_semver":"0.5.0",
        "network":network,
        "application_id":application_id,
        "canonical_uri":canonical_uri,
        "category_schema":"KTAPEOUT-APPLICATION-CATEGORY-V1",
        "display_name":display_name,
        "primary_category":"other",
        "secondary_categories":[],
        "tags":[],
        "surfaces":["web"],
        "status":"UNCLASSIFIED",
        "owner_authority":owner,
        "metadata_revision":1,
        "previous_metadata_hash":Value::Null,
        "effective_at":"2026-09-30T00:00:00Z",
        "metadata_id":"0".repeat(64)
    });
    let mut unsigned = body.as_object().cloned().unwrap_or_default();
    unsigned.remove("metadata_id");
    body["metadata_id"] = Value::String(metadata_digest(&Value::Object(unsigned))?);
    validate(&body, Some(network))
}
