//! Name-space completeness for the Compact name families.
//!
//! Live Gaps `[lo, hi)` and single-key Deeds (or reserved keys) tile `[0, 2^256)` exactly. Given the
//! full key list, the expected Gaps are determined; if every one of them is live, any key outside
//! the list lies in a live Gap and is therefore unregistered. This module is the pure, keyless part:
//! deriving Gap addresses and querying nodes is done by the external read adapter.

use num_bigint::BigUint;
use serde_json::{json, Value};

const ZERO_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    pub lo: String,
    pub hi: String,
    pub hi_is_max: bool,
}

impl Gap {
    pub fn to_json(&self) -> Value {
        json!({"lo": self.lo, "hi": self.hi, "hiIsMax": u8::from(self.hi_is_max)})
    }

    pub fn from_json(value: &Value) -> Result<Gap, String> {
        let object = value.as_object().ok_or("GAP_INVALID")?;
        let hex = |key: &str| {
            object
                .get(key)
                .and_then(Value::as_str)
                .filter(|s| is_hex64(s))
                .map(str::to_lowercase)
        };
        let hi_is_max = match object.get("hiIsMax").and_then(Value::as_u64) {
            Some(0) => false,
            Some(1) => true,
            _ => return Err("GAP_INVALID".into()),
        };
        Ok(Gap {
            lo: hex("lo").ok_or("GAP_INVALID")?,
            hi: hex("hi").ok_or("GAP_INVALID")?,
            hi_is_max,
        })
    }

    fn bounds(&self) -> Result<(BigUint, BigUint), String> {
        let lo = parse(&self.lo).map_err(|_| "NAME_SPACE_TILING_INVALID")?;
        if self.hi_is_max {
            return if self.hi == ZERO_HEX {
                Ok((lo, keyspace()))
            } else {
                Err("NAME_SPACE_TILING_INVALID".into())
            };
        }
        Ok((
            lo,
            parse(&self.hi).map_err(|_| "NAME_SPACE_TILING_INVALID")?,
        ))
    }
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn keyspace() -> BigUint {
    BigUint::from(1u8) << 256usize
}

fn parse(hex: &str) -> Result<BigUint, String> {
    if !is_hex64(hex) {
        return Err("KEY_INVALID".into());
    }
    BigUint::parse_bytes(hex.as_bytes(), 16).ok_or_else(|| "KEY_INVALID".to_owned())
}

fn to_hex(value: &BigUint) -> String {
    format!("{value:0>64x}")
}

/// The Gaps that must be live when `keys` are all the Deeds and reserved keys.
pub fn expected_gaps(keys: &[String]) -> Result<Vec<Gap>, String> {
    let mut parsed = keys
        .iter()
        .map(|key| parse(key))
        .collect::<Result<Vec<_>, _>>()?;
    parsed.sort();
    if parsed.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("DUPLICATE_KEY".into());
    }
    let mut gaps = Vec::with_capacity(parsed.len() + 1);
    let mut cursor = BigUint::from(0u8);
    for key in parsed {
        if key > cursor {
            gaps.push(Gap {
                lo: to_hex(&cursor),
                hi: to_hex(&key),
                hi_is_max: false,
            });
        }
        cursor = key + 1u8;
    }
    if cursor < keyspace() {
        gaps.push(Gap {
            lo: to_hex(&cursor),
            hi: ZERO_HEX.into(),
            hi_is_max: true,
        });
    }
    Ok(gaps)
}

/// Gaps plus single keys must cover `[0, 2^256)` with no overlap and no hole.
pub fn assert_tiling(gaps: &[Gap], keys: &[String]) -> Result<(), String> {
    let invalid = || "NAME_SPACE_TILING_INVALID".to_owned();
    let mut intervals = Vec::with_capacity(gaps.len() + keys.len());
    for key in keys {
        let value = parse(key).map_err(|_| invalid())?;
        intervals.push((value.clone(), value + 1u8));
    }
    for gap in gaps {
        let (lo, hi) = gap.bounds()?;
        if lo >= hi {
            return Err(invalid());
        }
        intervals.push((lo, hi));
    }
    intervals.sort();
    let mut cursor = BigUint::from(0u8);
    for (lo, hi) in intervals {
        if lo != cursor {
            return Err(invalid());
        }
        cursor = hi;
    }
    if cursor == keyspace() {
        Ok(())
    } else {
        Err(invalid())
    }
}

/// The 11-field state of an empty Gap, as the state-address derivation expects it.
pub fn gap_state_args(gap: &Gap) -> Value {
    json!([
        0,
        0,
        gap.lo,
        gap.hi,
        u8::from(gap.hi_is_max),
        ZERO_HEX,
        ZERO_HEX,
        ZERO_HEX,
        ZERO_HEX,
        ZERO_HEX,
        0
    ])
}

/// True iff `key` lies in one of the live gaps (half-open, max-aware).
pub fn key_is_absent(key: &str, live_gaps: &[Gap]) -> Result<bool, String> {
    let key = parse(key)?;
    for gap in live_gaps {
        let (lo, hi) = gap.bounds()?;
        if key >= lo && key < hi {
            return Ok(true);
        }
    }
    Ok(false)
}
