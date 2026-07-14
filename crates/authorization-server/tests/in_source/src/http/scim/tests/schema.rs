use super::*;

// SCIM constants

#[test]
fn scim_user_schema_constant_matches_rfc() {
    assert_eq!(
        SCIM_USER_SCHEMA,
        "urn:ietf:params:scim:schemas:core:2.0:User"
    );
}

#[test]
fn scim_error_schema_constant_matches_rfc() {
    assert_eq!(
        SCIM_ERROR_SCHEMA,
        "urn:ietf:params:scim:api:messages:2.0:Error"
    );
}

#[test]
fn scim_list_schema_constant_matches_rfc() {
    assert_eq!(
        SCIM_LIST_SCHEMA,
        "urn:ietf:params:scim:api:messages:2.0:ListResponse"
    );
}

#[test]
fn scim_patch_schema_constant_matches_rfc() {
    assert_eq!(
        SCIM_PATCH_SCHEMA,
        "urn:ietf:params:scim:api:messages:2.0:PatchOp"
    );
}

#[test]
fn scim_service_provider_config_schema_constant_matches_rfc() {
    assert_eq!(
        SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA,
        "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
    );
}

#[test]
fn scim_schema_schema_constant_matches_rfc() {
    assert_eq!(
        SCIM_SCHEMA_SCHEMA,
        "urn:ietf:params:scim:schemas:core:2.0:Schema"
    );
}

#[test]
fn scim_resource_type_schema_constant_matches_rfc() {
    assert_eq!(
        SCIM_RESOURCE_TYPE_SCHEMA,
        "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
    );
}

// scim_base

#[test]
fn scim_base_is_identity_for_object() {
    let input = json!({"key": "value", "nested": {"inner": 42}});
    let output = scim_base(input.clone());
    assert_eq!(output, input);
}

#[test]
fn scim_base_is_identity_for_array() {
    let input = json!([1, 2, 3]);
    let output = scim_base(input.clone());
    assert_eq!(output, input);
}

#[test]
fn scim_base_is_identity_for_string() {
    let input = json!("scim-payload");
    let output = scim_base(input.clone());
    assert_eq!(output, input);
}

#[test]
fn scim_base_is_identity_for_number() {
    let input = json!(42);
    let output = scim_base(input.clone());
    assert_eq!(output, input);
}

#[test]
fn scim_base_is_identity_for_null() {
    let input = json!(null);
    let output = scim_base(input.clone());
    assert_eq!(output, input);
}

#[test]
fn scim_base_is_identity_for_boolean() {
    let input = json!(true);
    let output = scim_base(input.clone());
    assert_eq!(output, input);
}

// scim_error

#[actix_web::test]
async fn scim_error_response_uses_scim_error_schema() {
    let response = scim_error(StatusCode::BAD_REQUEST, "invalidValue", "email is required");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["schemas"], json!([SCIM_ERROR_SCHEMA]));
    assert_eq!(value["status"], "400");
    assert_eq!(value["scimType"], "invalidValue");
    assert_eq!(value["detail"], "email is required");
}

#[actix_web::test]
async fn scim_error_response_with_unauthorized_status() {
    let response = scim_error(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "missing bearer token",
    );
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["schemas"], json!([SCIM_ERROR_SCHEMA]));
    assert_eq!(value["status"], "401");
    assert_eq!(value["scimType"], "unauthorized");
    assert_eq!(value["detail"], "missing bearer token");
}

#[actix_web::test]
async fn scim_error_response_with_forbidden_status() {
    let response = scim_error(
        StatusCode::FORBIDDEN,
        "forbidden",
        "SCIM token lacks the required scope",
    );
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["schemas"], json!([SCIM_ERROR_SCHEMA]));
    assert_eq!(value["status"], "403");
    assert_eq!(value["scimType"], "forbidden");
    assert_eq!(value["detail"], "SCIM token lacks the required scope");
}

#[actix_web::test]
async fn scim_error_response_with_not_found_status() {
    let response = scim_error(StatusCode::NOT_FOUND, "notFound", "user not found");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["schemas"], json!([SCIM_ERROR_SCHEMA]));
    assert_eq!(value["status"], "404");
    assert_eq!(value["scimType"], "notFound");
    assert_eq!(value["detail"], "user not found");
}

#[actix_web::test]
async fn scim_error_response_with_conflict_status() {
    let response = scim_error(
        StatusCode::CONFLICT,
        "uniqueness",
        "userName or email already exists",
    );
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["schemas"], json!([SCIM_ERROR_SCHEMA]));
    assert_eq!(value["status"], "409");
    assert_eq!(value["scimType"], "uniqueness");
    assert_eq!(value["detail"], "userName or email already exists");
}

#[actix_web::test]
async fn scim_error_does_not_expose_extra_fields() {
    let response = scim_error(StatusCode::BAD_REQUEST, "invalidFilter", "bad filter");
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    let object = value.as_object().unwrap();
    assert!(object.contains_key("schemas"));
    assert!(object.contains_key("status"));
    assert!(object.contains_key("scimType"));
    assert!(object.contains_key("detail"));
    assert_eq!(object.len(), 4);
}

#[actix_web::test]
async fn scim_error_status_matches_http_status_code() {
    let response = scim_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    );
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["status"], "503");
    assert_eq!(value["scimType"], "server_error");
    assert_eq!(value["detail"], "backend unavailable");
}
