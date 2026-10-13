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

/// Longest group name accepted, in bytes. Keeps the encoded list bounded.
pub const MAX_GROUP_NAME_BYTES: usize = 64;
/// Most members one group may list on this device.
pub const MAX_MEMBERS_PER_GROUP: usize = 256;
/// Most groups one profile may hold.
pub const MAX_GROUPS: usize = 128;
/// Largest encoded group list [`GroupBook::load`] will parse.
pub const MAX_ENCODED_BYTES: usize = 256 * 1024;

/// Why a [`GroupBook`] operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupBookError {
    BadName,
    NameTooLong,
    AlreadyExists,
    NoSuchGroup,
    TooManyGroups,
    TooManyMembers,
    DuplicateMember,
    NoSuchMember,
    Malformed,
    TooLarge,
}

impl GroupBookError {
    pub fn label(self) -> &'static str {
        match self {
            Self::BadName => "group name is empty or has control characters",
            Self::NameTooLong => "group name is too long",
            Self::AlreadyExists => "group already exists",
            Self::NoSuchGroup => "no such group",
            Self::TooManyGroups => "too many groups",
            Self::TooManyMembers => "too many members in group",
            Self::DuplicateMember => "member already in group",
            Self::NoSuchMember => "member not in group",
            Self::Malformed => "group list is malformed",
            Self::TooLarge => "group list is too large",
        }
    }
}

fn check_name(name: &str) -> Result<(), GroupBookError> {
    if name.trim().is_empty() || name.chars().any(|c| c.is_control()) {
        return Err(GroupBookError::BadName);
    }
    if name.len() > MAX_GROUP_NAME_BYTES {
        return Err(GroupBookError::NameTooLong);
    }
    Ok(())
}

/// In-memory group list owned by Rust (Android maximum-Rust step 2).
///
/// The Kotlin shell only renders what this returns and hands the encoded
/// bytes to the Keystore for wrapping. All validation and limits live here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupBook {
    groups: BTreeMap<String, Vec<u32>>,
}

impl GroupBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the book with a decoded list. Accepts the current
    /// `name<TAB>ids` layout and the legacy Kotlin `name:ids` layout
    /// (lines without a tab), so existing `groups.enc` files migrate.
    /// Any invalid row rejects the whole list and leaves the book unchanged.
    pub fn load(&mut self, raw: &[u8]) -> Result<(), GroupBookError> {
        if raw.len() > MAX_ENCODED_BYTES {
            return Err(GroupBookError::TooLarge);
        }
        let text = std::str::from_utf8(raw).map_err(|_| GroupBookError::Malformed)?;
        let mut next = GroupBook::new();
        for line in text.lines() {
            if line.is_empty() {
                continue;
            }
            let (name, ids) = match line.split_once('\t') {
                Some(pair) => pair,
                None => line.rsplit_once(':').ok_or(GroupBookError::Malformed)?,
            };
            next.create_or_replace(name)?;
            if !ids.is_empty() {
                for part in ids.split(',') {
                    let id: u32 = part.trim().parse().map_err(|_| GroupBookError::Malformed)?;
                    match next.add_member(name, id) {
                        Ok(()) | Err(GroupBookError::DuplicateMember) => {}
                        Err(e) => return Err(e),
                    }
                }
            }
        }
        *self = next;
        Ok(())
    }

    fn create_or_replace(&mut self, name: &str) -> Result<(), GroupBookError> {
        check_name(name)?;
        if !self.groups.contains_key(name) && self.groups.len() >= MAX_GROUPS {
            return Err(GroupBookError::TooManyGroups);
        }
        self.groups.insert(name.to_string(), Vec::new());
        Ok(())
    }

    /// Encode with [`encode_groups`] (sorted by name, stable).
    pub fn export(&self) -> Vec<u8> {
        let records: Vec<GroupRecord> = self.records();
        // Names were validated on insert, so encoding cannot fail.
        encode_groups(&records).unwrap_or_default()
    }

    pub fn records(&self) -> Vec<GroupRecord> {
        self.groups
            .iter()
            .map(|(name, ids)| GroupRecord {
                name: name.clone(),
                member_ids: ids.clone(),
            })
            .collect()
    }

    pub fn create(&mut self, name: &str) -> Result<(), GroupBookError> {
        check_name(name)?;
        if self.groups.contains_key(name) {
            return Err(GroupBookError::AlreadyExists);
        }
        self.create_or_replace(name)
    }

    pub fn remove_group(&mut self, name: &str) -> Result<Vec<u32>, GroupBookError> {
        self.groups.remove(name).ok_or(GroupBookError::NoSuchGroup)
    }

    pub fn add_member(&mut self, name: &str, id: u32) -> Result<(), GroupBookError> {
        let ids = self
            .groups
            .get_mut(name)
            .ok_or(GroupBookError::NoSuchGroup)?;
        if ids.contains(&id) {
            return Err(GroupBookError::DuplicateMember);
        }
        if ids.len() >= MAX_MEMBERS_PER_GROUP {
            return Err(GroupBookError::TooManyMembers);
        }
        ids.push(id);
        Ok(())
    }

    pub fn remove_member(&mut self, name: &str, id: u32) -> Result<(), GroupBookError> {
        let ids = self
            .groups
            .get_mut(name)
            .ok_or(GroupBookError::NoSuchGroup)?;
        let pos = ids
            .iter()
            .position(|m| *m == id)
            .ok_or(GroupBookError::NoSuchMember)?;
        ids.remove(pos);
        Ok(())
    }

    pub fn names(&self) -> Vec<String> {
        self.groups.keys().cloned().collect()
    }

    pub fn members(&self, name: &str) -> Option<&[u32]> {
        self.groups.get(name).map(|v| v.as_slice())
    }

    pub fn len(&self) -> usize {
        self.groups.len()
    }

    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    pub fn clear(&mut self) {
        self.groups.clear();
    }
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

    #[test]
    fn book_ops_and_limits() {
        let mut b = GroupBook::new();
        b.create("family").unwrap();
        assert_eq!(b.create("family"), Err(GroupBookError::AlreadyExists));
        assert_eq!(b.create("  "), Err(GroupBookError::BadName));
        assert_eq!(b.create("a\u{7}b"), Err(GroupBookError::BadName));
        assert_eq!(
            b.create(&"x".repeat(MAX_GROUP_NAME_BYTES + 1)),
            Err(GroupBookError::NameTooLong)
        );
        b.add_member("family", 3).unwrap();
        b.add_member("family", 7).unwrap();
        assert_eq!(
            b.add_member("family", 3),
            Err(GroupBookError::DuplicateMember)
        );
        assert_eq!(b.add_member("nope", 1), Err(GroupBookError::NoSuchGroup));
        b.remove_member("family", 3).unwrap();
        assert_eq!(
            b.remove_member("family", 3),
            Err(GroupBookError::NoSuchMember)
        );
        assert_eq!(b.members("family"), Some(&[7u32][..]));
        for i in 0..(MAX_MEMBERS_PER_GROUP as u32 - 1) {
            b.add_member("family", 100 + i).unwrap();
        }
        assert_eq!(
            b.add_member("family", 9),
            Err(GroupBookError::TooManyMembers)
        );
        assert_eq!(
            b.remove_group("family").unwrap().len(),
            MAX_MEMBERS_PER_GROUP
        );
        assert!(b.is_empty());
        for i in 0..MAX_GROUPS {
            b.create(&format!("g{i}")).unwrap();
        }
        assert_eq!(b.create("one-more"), Err(GroupBookError::TooManyGroups));
    }

    #[test]
    fn book_load_export_and_legacy_migration() {
        let mut b = GroupBook::new();
        b.create("work").unwrap();
        b.add_member("work", 5).unwrap();
        b.create("home").unwrap();
        let enc = b.export();
        let mut c = GroupBook::new();
        c.load(&enc).unwrap();
        assert_eq!(b, c);

        // Legacy Kotlin layout "name:id,id".
        let mut legacy = GroupBook::new();
        legacy.load(b"club:1,2\nsolo:\n").unwrap();
        assert_eq!(legacy.names(), vec!["club".to_string(), "solo".to_string()]);
        assert_eq!(legacy.members("club"), Some(&[1u32, 2][..]));

        // A bad row rejects the whole list and keeps the old state.
        assert_eq!(c.load(b"ok\t1\nbad\tx"), Err(GroupBookError::Malformed));
        assert_eq!(b, c);
        assert_eq!(
            c.load(&vec![b'a'; MAX_ENCODED_BYTES + 1]),
            Err(GroupBookError::TooLarge)
        );
        assert_eq!(c.load(&[0xff, 0xfe]), Err(GroupBookError::Malformed));
    }
}
