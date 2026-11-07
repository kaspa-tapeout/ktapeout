//! Bounded structural verification for decrypted KTAPEOUT private directory trees.
//!
//! This module validates V2 page commitments and the complete Root-to-Page-to-Object
//! graph. It does not decrypt objects, validate transaction bytes, authenticate
//! Receipts, select a chain head, or establish that the caller obtained evidence
//! from independent sources. Those checks belong to the trusted Host and the
//! action-specific Native transaction verifier.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const ROOT_SCHEMA: &str = "KTAPEOUT-PRIVATE-DIRECTORY-TREE-ROOT-V2";
// V3 differs by one field: the whole tree as a single embedded leaf page, in place of a published page.
const ROOT_SCHEMA_V3: &str = "KTAPEOUT-PRIVATE-DIRECTORY-TREE-ROOT-V3";
const PAGE_SCHEMA: &str = "KTAPEOUT-PRIVATE-DIRECTORY-TREE-PAGE-V2";
const PAGE_REF_SCHEMA: &str = "KTAPEOUT-PRIVATE-DIRECTORY-TREE-PAGE-REFERENCE-V2";
const OBJECT_SET_EMPTY_DOMAIN: &str = "KTAPEOUT/0.5.0/PRIVATE-DIRECTORY-OBJECT-SET-EMPTY/V2";
const OBJECT_SET_LEAF_DOMAIN: &str = "KTAPEOUT/0.5.0/PRIVATE-DIRECTORY-OBJECT-SET-LEAF/V2";
const OBJECT_SET_BRANCH_DOMAIN: &str = "KTAPEOUT/0.5.0/PRIVATE-DIRECTORY-OBJECT-SET-BRANCH/V2";
const PAGE_DOMAIN: &str = "KTAPEOUT/0.5.0/PRIVATE-DIRECTORY-PAGE/V2";

/// Hard bounds matching the KTAPEOUT Browser SDK V2 directory-tree contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateDirectoryTreeV2Limits {
    /// Maximum number of directory objects in one tree.
    pub max_objects: usize,
    /// Maximum number of encrypted pages referenced by one tree.
    pub max_pages: usize,
    /// Maximum number of object summaries in a leaf page.
    pub max_leaf_objects: usize,
    /// Maximum number of child references in a branch page.
    pub max_branch_children: usize,
    /// Maximum canonical plaintext size of a page, in bytes.
    pub max_page_plaintext_bytes: usize,
}

/// Limits used by the KTAPEOUT 0.5.0 Browser SDK V2 tree contract.
pub const PRIVATE_DIRECTORY_TREE_V2_LIMITS: PrivateDirectoryTreeV2Limits =
    PrivateDirectoryTreeV2Limits {
        max_objects: 65_536,
        max_pages: 8_192,
        max_leaf_objects: 64,
        max_branch_children: 16,
        max_page_plaintext_bytes: 32 * 1024,
    };

/// Recompute and verify a decrypted V2 directory tree supplied as a root and
/// page rows (`{"reference": ..., "page": ...}`). Rows must be sorted by
/// `reference.object_id`; each reachable page must occur exactly once and no
/// unreachable page is accepted. The returned summary is structural evidence
/// only and must be combined with authenticated transaction/Receipt checks by
/// a trusted Host.
///
/// The function is deterministic and performs no I/O, signing, or network work.
/// All collections and page plaintexts are checked against the fixed V2 limits.
///
/// # Errors
/// Returns stable `PRIVATE_DIRECTORY_TREE_V2_*` error codes for invalid shape,
/// ordering, digest, reference, or size bounds.
pub fn verify_private_directory_tree_v2(
    root: Value,
    page_rows: Vec<Value>,
) -> Result<Value, String> {
    if page_rows.len() > PRIVATE_DIRECTORY_TREE_V2_LIMITS.max_pages {
        return fail("PAGE_LIMIT");
    }
    let inline = root.get("schema").and_then(Value::as_str) == Some(ROOT_SCHEMA_V3);
    let mut root_fields = vec![
        "schema",
        "account",
        "network",
        "application_id",
        "space_id",
        "epoch",
        "revision",
        "previous_root_digest",
        "object_count",
        "object_set_root",
        "tree_reference",
        "application_metadata",
    ];
    if inline {
        root_fields.push("inline_page");
    }
    exact_fields(&root, &root_fields, "ROOT_FIELDS_INVALID")?;
    if string(&root, "schema")? != ROOT_SCHEMA && !inline {
        return fail("ROOT_SCHEMA_INVALID");
    }
    for name in ["account", "network", "application_id", "space_id"] {
        let value = string(&root, name)?;
        if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
            return fail("ROOT_SCOPE_INVALID");
        }
    }
    let object_count = uint(
        &root,
        "object_count",
        PRIVATE_DIRECTORY_TREE_V2_LIMITS.max_objects,
    )?;
    uint(&root, "epoch", u32::MAX as usize)?;
    uint(&root, "revision", u32::MAX as usize)?;
    let root_set = hash(&root, "object_set_root")?;
    if root
        .get("application_metadata")
        .and_then(Value::as_object)
        .is_none()
    {
        return fail("ROOT_METADATA_INVALID");
    }
    match root.get("previous_root_digest") {
        Some(Value::Null) => {}
        Some(Value::String(value)) if valid_hash(value) => {}
        _ => return fail("ROOT_PREVIOUS_DIGEST_INVALID"),
    }

    let mut pages = BTreeMap::<String, (Value, Value)>::new();
    let mut previous_id: Option<String> = None;
    for mut row in page_rows {
        exact_fields(&row, &["reference", "page"], "PAGE_ROW_FIELDS_INVALID")?;
        let row_object = row
            .as_object_mut()
            .ok_or("PRIVATE_DIRECTORY_TREE_V2_PAGE_ROW_INVALID")?;
        let reference = row_object
            .remove("reference")
            .ok_or("PRIVATE_DIRECTORY_TREE_V2_REFERENCE_MISSING")?;
        let page = row_object
            .remove("page")
            .ok_or("PRIVATE_DIRECTORY_TREE_V2_PAGE_MISSING")?;
        let checked = validate_reference(&reference)?;
        if previous_id
            .as_ref()
            .is_some_and(|previous| previous >= &checked.object_id)
        {
            return fail("PAGE_ROWS_NOT_SORTED");
        }
        previous_id = Some(checked.object_id.clone());
        if pages
            .insert(checked.object_id.clone(), (reference, page))
            .is_some()
        {
            return fail("PAGE_DUPLICATE");
        }
    }

    if inline {
        // The embedded page is the whole tree: no published page, no reference, and its commitment is the root's.
        if !pages.is_empty()
            || !matches!(root.get("tree_reference"), Some(Value::Null))
            || object_count == 0
        {
            return fail("ROOT_INLINE_PAGE_INVALID");
        }
        let page = root
            .get("inline_page")
            .ok_or("PRIVATE_DIRECTORY_TREE_V2_ROOT_INLINE_PAGE_INVALID")?;
        let synthetic = PageReference {
            object_id: String::new(),
            prefix: String::new(),
            kind: "leaf".to_string(),
            page_digest: digest_bytes(PAGE_DOMAIN, &canonical_json(page)?),
            object_set_root: root_set.clone(),
            object_count,
        };
        let (set_root, count, _children, _ids) = verify_page(page, &synthetic)?;
        if set_root != root_set || count != object_count {
            return fail("ROOT_OBJECT_SET_MISMATCH");
        }
        return Ok(json!({
            "schema": "KTAPEOUT-PRIVATE-DIRECTORY-TREE-V2-VERIFY-RESULT",
            "status": "PASS",
            "object_count": object_count,
            "page_count": 0,
            "object_set_root": root_set,
            "verification_digest": digest_json("KTAPEOUT/0.5.0/PRIVATE-DIRECTORY-TREE-VERIFY-RESULT/V1", &json!({
                "root": root_projection(&root),
                "page_summaries": []
            }))?,
        }));
    }

    let tree_reference = match root.get("tree_reference") {
        Some(Value::Null) if object_count == 0 => {
            if !pages.is_empty() || root_set != digest_text(OBJECT_SET_EMPTY_DOMAIN, "") {
                return fail("EMPTY_TREE_MISMATCH");
            }
            return Ok(json!({
                "schema": "KTAPEOUT-PRIVATE-DIRECTORY-TREE-V2-VERIFY-RESULT",
                "status": "PASS",
                "object_count": 0,
                "page_count": 0,
                "object_set_root": root_set,
                "verification_digest": digest_json("KTAPEOUT/0.5.0/PRIVATE-DIRECTORY-TREE-VERIFY-RESULT/V1", &json!({
                    "root": root_projection(&root),
                    "page_summaries": []
                }))?,
            }));
        }
        Some(Value::Object(_)) if object_count > 0 => root
            .get("tree_reference")
            .ok_or("PRIVATE_DIRECTORY_TREE_V2_TREE_REFERENCE_MISSING")?,
        _ => return fail("ROOT_TREE_REFERENCE_INVALID"),
    };
    let root_reference = validate_reference(tree_reference)?;
    if !root_reference.prefix.is_empty()
        || root_reference.object_count != object_count
        || root_reference.object_set_root != root_set
    {
        return fail("ROOT_TREE_REFERENCE_MISMATCH");
    }
    if pages.is_empty() {
        return fail("TREE_PAGES_MISSING");
    }

    let mut visited = BTreeSet::new();
    let mut stack = vec![tree_reference.clone()];
    let mut object_ids = BTreeSet::new();
    while let Some(expected_reference) = stack.pop() {
        let expected = validate_reference(&expected_reference)?;
        let page_id = expected.object_id.clone();
        if !visited.insert(page_id.clone()) {
            return fail("PAGE_GRAPH_DUPLICATE_OR_CYCLE");
        }
        let (reference, page) = pages
            .get(&page_id)
            .ok_or("PRIVATE_DIRECTORY_TREE_V2_PAGE_MISSING")?;
        if canonical_json(reference)? != canonical_json(&expected_reference)? {
            return fail("PAGE_REFERENCE_EDGE_MISMATCH");
        }
        let checked_reference = validate_reference(reference)?;
        let (set_root, count, children, objects) = verify_page(page, &checked_reference)?;
        if set_root != checked_reference.object_set_root || count != checked_reference.object_count
        {
            return fail("PAGE_REFERENCE_MISMATCH");
        }
        if let Some(child_references) = children {
            for child in child_references.iter().rev() {
                stack.push(child.clone());
            }
        }
        for object_id in objects {
            if !object_ids.insert(object_id) {
                return fail("OBJECT_DUPLICATE");
            }
            if object_ids.len() > PRIVATE_DIRECTORY_TREE_V2_LIMITS.max_objects {
                return fail("OBJECT_LIMIT");
            }
        }
    }
    if visited.len() != pages.len() {
        return fail("UNREACHABLE_PAGE");
    }
    if object_ids.len() != object_count {
        return fail("OBJECT_COUNT_MISMATCH");
    }

    let page_summaries: Vec<Value> = pages
        .values()
        .map(|(reference, _)| page_summary(reference))
        .collect::<Result<_, _>>()?;
    Ok(json!({
        "schema": "KTAPEOUT-PRIVATE-DIRECTORY-TREE-V2-VERIFY-RESULT",
        "status": "PASS",
        "object_count": object_count,
        "page_count": visited.len(),
        "object_set_root": root_set,
        "verification_digest": digest_json("KTAPEOUT/0.5.0/PRIVATE-DIRECTORY-TREE-VERIFY-RESULT/V1", &json!({
            "root": root_projection(&root),
            "page_summaries": page_summaries,
        }))?,
    }))
}

#[derive(Debug)]
struct PageReference {
    object_id: String,
    prefix: String,
    kind: String,
    page_digest: String,
    object_set_root: String,
    object_count: usize,
}

type VerifiedPage = (String, usize, Option<Vec<Value>>, Vec<String>);

fn verify_page(page: &Value, reference: &PageReference) -> Result<VerifiedPage, String> {
    if string(page, "schema")? != PAGE_SCHEMA || string(page, "prefix")? != reference.prefix {
        return fail("PAGE_HEADER_MISMATCH");
    }
    let kind = string(page, "kind")?;
    if kind != reference.kind {
        return fail("PAGE_KIND_MISMATCH");
    }
    let page_bytes = canonical_json(page)?;
    if page_bytes.len() > PRIVATE_DIRECTORY_TREE_V2_LIMITS.max_page_plaintext_bytes {
        return fail("PAGE_BYTE_LIMIT");
    }
    if digest_bytes(PAGE_DOMAIN, &page_bytes) != reference.page_digest {
        return fail("PAGE_DIGEST_MISMATCH");
    }
    match kind {
        "leaf" => {
            exact_fields(
                page,
                &["schema", "prefix", "kind", "objects"],
                "LEAF_FIELDS_INVALID",
            )?;
            let objects = page
                .get("objects")
                .and_then(Value::as_array)
                .ok_or("PRIVATE_DIRECTORY_TREE_V2_LEAF_OBJECTS_INVALID")?;
            if objects.is_empty()
                || objects.len() > PRIVATE_DIRECTORY_TREE_V2_LIMITS.max_leaf_objects
            {
                return fail("LEAF_OBJECT_LIMIT");
            }
            let mut ids = Vec::with_capacity(objects.len());
            let mut materials = Vec::with_capacity(objects.len());
            let mut previous: Option<String> = None;
            for object in objects {
                let material = validate_object(object)?;
                if !material.object_id.starts_with(&reference.prefix)
                    || previous
                        .as_ref()
                        .is_some_and(|value| value >= &material.object_id)
                {
                    return fail("LEAF_OBJECT_ORDER_OR_PREFIX_INVALID");
                }
                previous = Some(material.object_id.clone());
                ids.push(material.object_id.clone());
                materials.push(material.value);
            }
            let digest = digest_json(
                OBJECT_SET_LEAF_DOMAIN,
                &json!({ "prefix": reference.prefix, "objects": materials }),
            )?;
            Ok((digest, ids.len(), None, ids))
        }
        "branch" => {
            exact_fields(
                page,
                &["schema", "prefix", "kind", "children"],
                "BRANCH_FIELDS_INVALID",
            )?;
            let children = page
                .get("children")
                .and_then(Value::as_array)
                .ok_or("PRIVATE_DIRECTORY_TREE_V2_CHILDREN_INVALID")?;
            if children.is_empty()
                || children.len() > PRIVATE_DIRECTORY_TREE_V2_LIMITS.max_branch_children
            {
                return fail("BRANCH_CHILD_LIMIT");
            }
            let mut ids = Vec::with_capacity(children.len());
            let mut materials = Vec::with_capacity(children.len());
            let mut count = 0usize;
            let mut prior_prefix: Option<String> = None;
            for child in children {
                let checked = validate_reference(child)?;
                if checked.prefix.len() != reference.prefix.len() + 1
                    || !checked.prefix.starts_with(&reference.prefix)
                    || prior_prefix
                        .as_ref()
                        .is_some_and(|prefix| prefix >= &checked.prefix)
                {
                    return fail("BRANCH_CHILD_PREFIX_OR_ORDER_INVALID");
                }
                prior_prefix = Some(checked.prefix.clone());
                count = count
                    .checked_add(checked.object_count)
                    .ok_or("PRIVATE_DIRECTORY_TREE_V2_OBJECT_COUNT_OVERFLOW")?;
                if count > PRIVATE_DIRECTORY_TREE_V2_LIMITS.max_objects {
                    return fail("OBJECT_LIMIT");
                }
                ids.push(child.clone());
                materials.push(
                    json!({ "prefix": checked.prefix, "object_count": checked.object_count,
                    "object_set_root": checked.object_set_root }),
                );
            }
            let digest = digest_json(
                OBJECT_SET_BRANCH_DOMAIN,
                &json!({ "prefix": reference.prefix, "children": materials }),
            )?;
            Ok((digest, count, Some(ids), Vec::new()))
        }
        _ => fail("PAGE_KIND_INVALID"),
    }
}

struct ObjectMaterial {
    object_id: String,
    value: Value,
}

fn validate_object(value: &Value) -> Result<ObjectMaterial, String> {
    exact_fields(
        value,
        &[
            "object_id",
            "payload_sha256",
            "payload_bytes",
            "transaction_ref",
        ],
        "OBJECT_FIELDS_INVALID",
    )?;
    let object_id = hash(value, "object_id")?;
    let payload_digest = hash(value, "payload_sha256")?;
    let payload_bytes = uint(value, "payload_bytes", 256 * 1024)?;
    if payload_bytes == 0 {
        return fail("OBJECT_PAYLOAD_BYTES_INVALID");
    }
    let transaction_ref = value
        .get("transaction_ref")
        .ok_or("PRIVATE_DIRECTORY_TREE_V2_TRANSACTION_REF_MISSING")?;
    exact_fields(
        transaction_ref,
        &[
            "schema",
            "transaction_id",
            "output_index",
            "containing_block_hash",
        ],
        "TRANSACTION_REF_FIELDS_INVALID",
    )?;
    if string(transaction_ref, "schema")? != "KTAPEOUT-PRIVATE-TRANSACTION-REFERENCE-V1" {
        return fail("TRANSACTION_REF_SCHEMA_INVALID");
    }
    hash(transaction_ref, "transaction_id")?;
    uint(transaction_ref, "output_index", 65_535)?;
    match transaction_ref.get("containing_block_hash") {
        Some(Value::Null) => {}
        Some(Value::String(value)) if valid_hash(value) => {}
        _ => return fail("TRANSACTION_REF_BLOCK_HASH_INVALID"),
    }
    Ok(ObjectMaterial {
        object_id: object_id.clone(),
        value: json!({ "object_id": object_id, "payload_sha256": payload_digest,
            "payload_bytes": payload_bytes, "transaction_ref": transaction_ref }),
    })
}

fn validate_reference(value: &Value) -> Result<PageReference, String> {
    exact_fields(
        value,
        &[
            "schema",
            "prefix",
            "kind",
            "object_id",
            "page_digest",
            "object_set_root",
            "object_count",
            "payload_sha256",
            "payload_bytes",
            "transaction_ref",
        ],
        "PAGE_REFERENCE_FIELDS_INVALID",
    )?;
    if string(value, "schema")? != PAGE_REF_SCHEMA {
        return fail("PAGE_REFERENCE_SCHEMA_INVALID");
    }
    let prefix = string(value, "prefix")?.to_owned();
    if prefix.len() > 64
        || !prefix
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return fail("PAGE_PREFIX_INVALID");
    }
    let kind = string(value, "kind")?.to_owned();
    if kind != "leaf" && kind != "branch" {
        return fail("PAGE_KIND_INVALID");
    }
    let object_id = hash(value, "object_id")?;
    let page_digest = hash(value, "page_digest")?;
    let object_set_root = hash(value, "object_set_root")?;
    hash(value, "payload_sha256")?;
    let object_count = uint(
        value,
        "object_count",
        PRIVATE_DIRECTORY_TREE_V2_LIMITS.max_objects,
    )?;
    if object_count == 0 {
        return fail("PAGE_OBJECT_COUNT_INVALID");
    }
    let payload_bytes = uint(
        value,
        "payload_bytes",
        PRIVATE_DIRECTORY_TREE_V2_LIMITS.max_page_plaintext_bytes + 272,
    )?;
    if payload_bytes == 0 {
        return fail("PAGE_PAYLOAD_BYTES_INVALID");
    }
    validate_transaction_ref(
        value
            .get("transaction_ref")
            .ok_or("PRIVATE_DIRECTORY_TREE_V2_TRANSACTION_REF_MISSING")?,
    )?;
    Ok(PageReference {
        object_id,
        prefix,
        kind,
        page_digest,
        object_set_root,
        object_count,
    })
}

fn validate_transaction_ref(value: &Value) -> Result<(), String> {
    exact_fields(
        value,
        &[
            "schema",
            "transaction_id",
            "output_index",
            "containing_block_hash",
        ],
        "TRANSACTION_REF_FIELDS_INVALID",
    )?;
    if string(value, "schema")? != "KTAPEOUT-PRIVATE-TRANSACTION-REFERENCE-V1" {
        return fail("TRANSACTION_REF_SCHEMA_INVALID");
    }
    hash(value, "transaction_id")?;
    uint(value, "output_index", 65_535)?;
    match value.get("containing_block_hash") {
        Some(Value::Null) => Ok(()),
        Some(Value::String(value)) if valid_hash(value) => Ok(()),
        _ => fail("TRANSACTION_REF_BLOCK_HASH_INVALID"),
    }
}

fn page_summary(reference: &Value) -> Result<Value, String> {
    let checked = validate_reference(reference)?;
    Ok(
        json!({ "object_id": checked.object_id, "payload_sha256": reference["payload_sha256"],
        "payload_bytes": reference["payload_bytes"], "transaction_ref": reference["transaction_ref"],
        "page_digest": checked.page_digest, "object_set_root": checked.object_set_root,
        "object_count": checked.object_count, "prefix": checked.prefix, "kind": checked.kind }),
    )
}

fn root_projection(root: &Value) -> Value {
    let mut projection = json!({
        "schema": root["schema"],
        "account": root["account"],
        "network": root["network"],
        "application_id": root["application_id"],
        "space_id": root["space_id"],
        "epoch": root["epoch"],
        "revision": root["revision"],
        "previous_root_digest": root["previous_root_digest"],
        "object_count": root["object_count"],
        "object_set_root": root["object_set_root"],
        "tree_reference": root["tree_reference"],
    });
    // V2 projections stay byte-identical; only a V3 root adds its embedded page.
    if let (Some(object), Some(page)) = (projection.as_object_mut(), root.get("inline_page")) {
        object.insert("inline_page".to_string(), page.clone());
    }
    projection
}

fn exact_fields(value: &Value, expected: &[&str], code: &str) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("PRIVATE_DIRECTORY_TREE_V2_{code}"))?;
    if object.len() != expected.len() || expected.iter().any(|field| !object.contains_key(*field)) {
        return fail(code);
    }
    Ok(())
}

fn string<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value.get(field).and_then(Value::as_str).ok_or_else(|| {
        format!(
            "PRIVATE_DIRECTORY_TREE_V2_{}_INVALID",
            field.to_ascii_uppercase()
        )
    })
}

fn uint(value: &Value, field: &str, max: usize) -> Result<usize, String> {
    let value = value.get(field).and_then(Value::as_u64).ok_or_else(|| {
        format!(
            "PRIVATE_DIRECTORY_TREE_V2_{}_INVALID",
            field.to_ascii_uppercase()
        )
    })?;
    let value = usize::try_from(value).map_err(|_| {
        format!(
            "PRIVATE_DIRECTORY_TREE_V2_{}_INVALID",
            field.to_ascii_uppercase()
        )
    })?;
    if value > max {
        return Err(format!(
            "PRIVATE_DIRECTORY_TREE_V2_{}_LIMIT",
            field.to_ascii_uppercase()
        ));
    }
    Ok(value)
}

fn hash(value: &Value, field: &str) -> Result<String, String> {
    let value = string(value, field)?;
    if !valid_hash(value) {
        return Err(format!(
            "PRIVATE_DIRECTORY_TREE_V2_{}_INVALID",
            field.to_ascii_uppercase()
        ));
    }
    Ok(value.to_owned())
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn canonical_json(value: &Value) -> Result<Vec<u8>, String> {
    super::canonical_json(value)
}

fn digest_json(domain: &str, value: &Value) -> Result<String, String> {
    let bytes = canonical_json(value)?;
    Ok(digest_bytes(domain, &bytes))
}

fn digest_text(domain: &str, value: &str) -> String {
    digest_bytes(domain, value.as_bytes())
}

fn digest_bytes(domain: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn fail<T>(code: &str) -> Result<T, String> {
    Err(format!("PRIVATE_DIRECTORY_TREE_V2_{code}"))
}
