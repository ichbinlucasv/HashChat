//! Group list persistence helpers (Android maximum-Rust migration).
//!
//! The Kotlin shell used to own group-name to member-id maps. This module holds
//! a pure, tested encoding so both desktop and Android can share one format.
//! Encryption stays with Keystore / session wrap — this is the plaintext layout
//! only, never written to disk by itself.

use std::collections::BTreeMap;

/// One group: a display name and ordered member ratchet ids (opaque to this crate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRecord {
    pub name: String,
    pub member_ids: Vec<u32>,
}

/// Encode groups as lines: `name<TAB>id,id,id` then newline. Names cannot contain tab or newline.
pub fn encode_groups(groups: &[GroupRecord]) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    for g in groups {
        if g.name.is_empty() {
            return Err("empty group name");
        }
        if g.name.contains('\t') || g.name.contains('\n') {
            return Err("group name has forbidden whitespace");
        }
        out.extend_from_slice(g.name.as_bytes());
        out.push(b'\t');
        for (i, id) in g.member_ids.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            out.extend_from_slice(id.to_string().as_bytes());
        }
        out.push(b'\n');
    }
    Ok(out)
}

/// Decode the layout from [`encode_groups`]. Duplicate names keep the last row.
pub fn decode_groups(raw: &[u8]) -> Result<Vec<GroupRecord>, &'static str> {
    let text = std::str::from_utf8(raw).map_err(|_| "group list is not utf-8")?;
    let mut map: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let (name, ids) = line.split_once('\t').ok_or("group line missing tab")?;
        if name.is_empty() {
            return Err("empty group name");
        }
        let mut member_ids = Vec::new();
        if !ids.is_empty() {
            for part in ids.split(',') {
                let id: u32 = part.parse().map_err(|_| "bad member id")?;
                member_ids.push(id);
            }
        }
        map.insert(name.to_string(), member_ids);
    }
    Ok(map
        .into_iter()
        .map(|(name, member_ids)| GroupRecord { name, member_ids })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_reject_bad_names() {
        let groups = vec![
            GroupRecord {
                name: "family".into(),
                member_ids: vec![1, 2, 9],
            },
            GroupRecord {
                name: "work".into(),
                member_ids: vec![],
            },
        ];
        let enc = encode_groups(&groups).unwrap();
        let back = decode_groups(&enc).unwrap();
        assert_eq!(back, groups);
        assert!(encode_groups(&[GroupRecord {
            name: "bad\tname".into(),
            member_ids: vec![1],
        }])
        .is_err());
        assert!(decode_groups(b"notab").is_err());
    }
}
