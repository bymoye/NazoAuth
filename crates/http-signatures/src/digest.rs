use sfv::{BareItem, Dictionary, ItemSerializer, ListEntry, Parser, Version};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Computes an RFC 9530 SHA-256 `Content-Digest` field value.
pub fn content_digest(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    format!(
        "sha-256={}",
        ItemSerializer::new().bare_item(digest.as_slice()).finish()
    )
}

/// Validates an RFC 9530 digest dictionary and its unique SHA-256 member.
pub fn content_digest_field_matches(field_value: &str, body: &[u8]) -> bool {
    let field_value = field_value.trim_matches([' ', '\t']);
    let Ok(dictionary): Result<Dictionary, _> = Parser::new(field_value)
        .with_version(Version::Rfc8941)
        .parse()
    else {
        return false;
    };
    if crate::verify::top_level_member_count(field_value) != dictionary.len()
        || raw_dictionary_key_count(field_value, "sha-256") != 1
        || dictionary.values().any(|entry| {
            !matches!(
                entry,
                ListEntry::Item(item)
                    if item.params.is_empty()
                        && matches!(item.bare_item, BareItem::ByteSequence(_))
            )
        })
    {
        return false;
    }
    let digest: [u8; 32] = match dictionary.get("sha-256") {
        Some(ListEntry::Item(item)) if item.params.is_empty() => match &item.bare_item {
            BareItem::ByteSequence(bytes) => match bytes.as_slice().try_into() {
                Ok(digest) => digest,
                Err(_) => return false,
            },
            _ => return false,
        },
        _ => return false,
    };
    let computed: [u8; 32] = Sha256::digest(body).into();
    bool::from(digest.ct_eq(&computed))
}

fn raw_dictionary_key_count(field: &str, wanted: &str) -> usize {
    field
        .split(',')
        .filter_map(|member| {
            member
                .trim_start()
                .split_once(['=', ';'])
                .map(|(key, _)| key)
                .or_else(|| Some(member.trim()))
        })
        .filter(|key| *key == wanted)
        .count()
}
