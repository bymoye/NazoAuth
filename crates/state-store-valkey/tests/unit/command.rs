use super::{COMPARE_DELETE_JSON_SCRIPT, COMPARE_DELETE_SCRIPT};

#[test]
fn compare_delete_checks_the_opaque_value_before_deleting() {
    let get = COMPARE_DELETE_SCRIPT.find("redis.call('GET'").unwrap();
    let compare = COMPARE_DELETE_SCRIPT.find("current ~= ARGV[1]").unwrap();
    let delete = COMPARE_DELETE_SCRIPT.find("redis.call('DEL'").unwrap();

    assert!(get < compare && compare < delete);
    assert!(COMPARE_DELETE_SCRIPT.contains("return 'changed'"));
    assert!(COMPARE_DELETE_SCRIPT.contains("return 'deleted'"));
}

#[test]
fn json_compare_delete_decodes_before_a_type_preserving_deep_compare() {
    let decode = COMPARE_DELETE_JSON_SCRIPT.find("pcall(parse_json").unwrap();
    let compare = COMPARE_DELETE_JSON_SCRIPT
        .find("json_equal(current, expected)")
        .unwrap();
    let delete = COMPARE_DELETE_JSON_SCRIPT.find("redis.call('DEL'").unwrap();

    assert!(decode < compare && compare < delete);
    assert!(COMPARE_DELETE_JSON_SCRIPT.contains("kind = 'array'"));
    assert!(COMPARE_DELETE_JSON_SCRIPT.contains("kind = 'object'"));
    assert!(COMPARE_DELETE_JSON_SCRIPT.contains("left.kind ~= right.kind"));
    assert!(COMPARE_DELETE_JSON_SCRIPT.contains("table.sort(left_keys)"));
    assert!(COMPARE_DELETE_JSON_SCRIPT.contains("return 'malformed'"));
}
