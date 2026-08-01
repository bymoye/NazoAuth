use super::*;

#[test]
fn resource_indicators_require_absolute_unique_fragmentless_uris() {
    assert_eq!(
        parse_resource_indicators(&["https://api.example".to_owned()]).unwrap(),
        ["https://api.example"]
    );
    assert_eq!(
        parse_resource_indicators(&["relative".to_owned()]),
        Err(ResourceIndicatorError::Invalid)
    );
    assert_eq!(
        parse_resource_indicators(&["https://api.example#fragment".to_owned()]),
        Err(ResourceIndicatorError::Invalid)
    );
}

#[test]
fn private_parameter_representation_uses_the_same_validation() {
    assert_eq!(
        parse_resource_indicator_parameter(Some("https://api.example")).unwrap(),
        ["https://api.example"]
    );
    let encoded = encode_resource_indicators(&[
        "https://api.example".to_owned(),
        "https://admin.example".to_owned(),
    ])
    .unwrap();
    assert_eq!(
        parse_resource_indicator_parameter(Some(&encoded)).unwrap(),
        ["https://api.example", "https://admin.example"]
    );
    assert!(encode_resource_indicators(&[]).is_none());
    assert_eq!(
        parse_resource_indicator_parameter(Some(
            r#"["https://api.example","https://api.example"]"#
        )),
        Err(ResourceIndicatorError::Invalid)
    );
}
