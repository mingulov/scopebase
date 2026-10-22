// SPDX-License-Identifier: Apache-2.0
//! Package-local120-byte reference-policy controls; no public crypto API.
#![allow(dead_code)]
pub fn fold(raw: &[u8], count: usize, checked: bool) -> Result<[u64; 15], String> {
    if raw.len() != count.checked_mul(120).ok_or("aggregate extent")? {
        return Err("aggregate requires 120-byte lanes".into());
    }
    let mut words = [0u64; 15];
    for lane in raw.chunks_exact(120) {
        for (i, word) in words.iter_mut().enumerate() {
            let n = u64::from_le_bytes(lane[i * 8..i * 8 + 8].try_into().unwrap());
            if checked {
                if n == u64::MAX {
                    return Err("saturated aggregate input".into());
                }
                *word = word.checked_add(n).ok_or("aggregate overflow")?;
            } else {
                *word = word.saturating_add(n);
            }
        }
    }
    Ok(words)
}
pub fn totals<F>(
    slots: u32,
    count: usize,
    checked: bool,
    mut lookup: F,
) -> Result<Option<[u64; 15]>, String>
where
    F: FnMut(&[u8]) -> Result<Option<Vec<u8>>, String>,
{
    let mut all = Vec::new();
    for slot in 0..slots {
        let Some(raw) = lookup(&slot.to_le_bytes())? else {
            if slot == 0 {
                return Ok(None);
            }
            return Err("later totals slot disappeared".into());
        };
        if raw.len() != count * 120 {
            return Err("totals requires 120-byte lanes".into());
        }
        all.extend_from_slice(&raw);
    }
    fold(&all, count * slots as usize, checked).map(Some)
}
pub fn diagnostic<F>(count: usize, mut lookup: F) -> Result<Vec<u64>, String>
where
    F: FnMut(&[u8]) -> Result<Option<Vec<u8>>, String>,
{
    let raw = lookup(&0u32.to_le_bytes())?.ok_or("mandatory diagnostic absent")?;
    if raw.len() != count * 8 {
        return Err("diagnostic requires 8-byte lanes".into());
    }
    Ok(raw
        .chunks_exact(8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .collect())
}
pub fn terminal<F>(topology: Option<usize>, mut lookup: F) -> Result<(), String>
where
    F: FnMut() -> Result<(), String>,
{
    topology
        .filter(|n| *n > 0)
        .ok_or("unavailable possible topology")?;
    lookup()
}
/// Reference KAGG row policy: caller owns enumeration; reuse decoded lane
/// storage and abort the entire walk on a disappeared known260-byte key.
pub fn walk<F>(keys: &[&[u8]], count: usize, mut lookup: F) -> Result<Vec<[u64; 15]>, String>
where
    F: FnMut(&[u8]) -> Result<Option<Vec<u8>>, String>,
{
    let mut lanes = Vec::with_capacity(count);
    let mut out = Vec::new();
    for key in keys {
        if key.len() != 260 {
            return Err("aggregate key requires260 bytes".into());
        }
        let raw = lookup(key)?.ok_or("known aggregate key disappeared")?;
        if raw.len() != count * 120 {
            return Err("aggregate requires120-byte lanes".into());
        }
        lanes.clear();
        for raw in raw.chunks_exact(120) {
            let mut words = [0; 15];
            for (i, n) in words.iter_mut().enumerate() {
                *n = u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap());
            }
            lanes.push(words);
        }
        let mut sum = [0u64; 15];
        for lane in &lanes {
            for (i, n) in lane.iter().enumerate() {
                sum[i] = sum[i].saturating_add(*n);
            }
        }
        out.push(sum);
    }
    Ok(out)
}
