use std::{
    fs,
    sync::{Arc, RwLock},
};

use actix_web::{
    body::to_bytes,
    web::{Data, Json},
};

use super::*;

fn endpoint(
    expected_token_hash: Option<String>,
    token_path: PathBuf,
) -> InitialAdminBootstrapEndpoint {
    endpoint_with_deployment(expected_token_hash, token_path, DEPLOYMENT_ID)
}

fn endpoint_with_deployment(
    expected_token_hash: Option<String>,
    token_path: PathBuf,
    expected_deployment_id: &str,
) -> InitialAdminBootstrapEndpoint {
    let pool =
        nazo_postgres::create_pool("postgresql://unused:unused@127.0.0.1:1/unused", 1).unwrap();
    InitialAdminBootstrapEndpoint {
        repository: nazo_postgres::InitialAdminBootstrapRepository::new(
            pool,
            nazo_identity::TenantContext::default_system(),
        ),
        expected_token_hash: Arc::new(RwLock::new(expected_token_hash)),
        token_path,
        expected_deployment_id: expected_deployment_id.to_owned(),
    }
}

const REQUEST_ID: &str = "bootstrap-admin-0123456789abcdef0123456789abcdef";
const TOKEN: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
const DEPLOYMENT_ID: &str = "deploy-test";

fn claim_request(
    token: &str,
    deployment_id: &str,
    email: &str,
    password: String,
) -> InitialAdminClaimRequest {
    InitialAdminClaimRequest {
        request_id: REQUEST_ID.to_owned(),
        token: token.to_owned(),
        deployment_id: deployment_id.to_owned(),
        email: email.to_owned(),
        password,
    }
}

#[test]
fn claim_request_is_closed_json() {
    let valid = br#"{"request_id":"bootstrap-admin-0123456789abcdef0123456789abcdef","token":"token","deployment_id":"deploy-x","email":"admin@example.com","password":"correct horse battery staple"}"#;
    assert!(serde_json::from_slice::<InitialAdminClaimRequest>(valid).is_ok());
    let no_deployment = br#"{"request_id":"bootstrap-admin-0123456789abcdef0123456789abcdef","token":"token","email":"admin@example.com","password":"correct horse battery staple"}"#;
    assert!(serde_json::from_slice::<InitialAdminClaimRequest>(no_deployment).is_err());
    let unknown = br#"{"request_id":"bootstrap-admin-0123456789abcdef0123456789abcdef","token":"token","deployment_id":"deploy-x","email":"admin@example.com","password":"correct horse battery staple","next":"/ui/auth"}"#;
    assert!(serde_json::from_slice::<InitialAdminClaimRequest>(unknown).is_err());
}

#[test]
fn request_id_is_closed_and_non_secret() {
    assert!(valid_bootstrap_request_id(
        "bootstrap-admin-0123456789abcdef0123456789abcdef"
    ));
    assert!(!valid_bootstrap_request_id("request-0123"));
    assert!(!valid_bootstrap_request_id(
        "bootstrap-admin-0123456789ABCDEF0123456789ABCDEF"
    ));
}

#[test]
fn bootstrap_token_format_matches_the_48_byte_base64url_generator() {
    assert!(valid_initial_admin_token(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
    ));
    assert!(!valid_initial_admin_token(&"a".repeat(63)));
    assert!(!valid_initial_admin_token(&"a".repeat(65)));
    assert!(!valid_initial_admin_token(&format!("{}+", "a".repeat(63))));
}

#[actix_web::test]
async fn claim_rejects_closed_invalid_and_malformed_inputs_before_persistence() {
    let token_path = std::env::temp_dir().join(format!(
        "nazoauth-bootstrap-token-test-{}",
        rand::random::<u64>()
    ));
    let closed = Data::new(endpoint(None, token_path.clone()));
    let response = claim_initial_admin(
        closed,
        Json(claim_request(
            "token",
            DEPLOYMENT_ID,
            "admin@example.com",
            "correct horse battery staple".to_owned(),
        )),
    )
    .await;
    assert_eq!(response.status(), StatusCode::GONE);

    let ready = Data::new(endpoint(Some(hash_token(TOKEN)), token_path.clone()));
    let response = claim_initial_admin(
        ready.clone(),
        Json(claim_request(
            "wrong",
            DEPLOYMENT_ID,
            "admin@example.com",
            "correct horse battery staple".to_owned(),
        )),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let response = claim_initial_admin(
        ready.clone(),
        Json(claim_request(
            TOKEN,
            DEPLOYMENT_ID,
            "not-an-email",
            "correct horse battery staple".to_owned(),
        )),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    for password in ["short".to_owned(), "x".repeat(1025)] {
        let response = claim_initial_admin(
            ready.clone(),
            Json(claim_request(
                TOKEN,
                DEPLOYMENT_ID,
                "admin@example.com",
                password,
            )),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    ready.close();
    assert!(ready.expected_token_hash().is_none());
}

#[actix_web::test]
async fn deployment_id_binding_rejects_mismatched_or_unexpected_claims_before_persistence() {
    let token_path = std::env::temp_dir().join(format!(
        "nazoauth-bootstrap-deployment-test-{}",
        rand::random::<u64>()
    ));

    // A server started with DEPLOYMENT_ID only accepts that exact identity.
    let bound = Data::new(endpoint_with_deployment(
        Some(hash_token(TOKEN)),
        token_path.clone(),
        "deploy-abc123",
    ));
    for presented in ["deploy-other", "", " deploy-abc123 "] {
        let response = claim_initial_admin(
            bound.clone(),
            Json(claim_request(
                TOKEN,
                presented,
                "admin@example.com",
                "correct horse battery staple".to_owned(),
            )),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap();
        assert_eq!(body["error"], "deployment_mismatch");
    }
}

#[actix_web::test]
async fn a_deployment_bound_claim_passes_the_identity_gate() {
    let token_path = std::env::temp_dir().join(format!(
        "nazoauth-bootstrap-deployment-pass-{}",
        rand::random::<u64>()
    ));
    fs::write(&token_path, TOKEN).unwrap();
    let bound = Data::new(endpoint_with_deployment(
        Some(hash_token(TOKEN)),
        token_path.clone(),
        "deploy-abc123",
    ));

    // The pool is unreachable, so the request must reach exactly the
    // persistence-unavailable boundary — proving every earlier gate,
    // including the deployment binding, accepted the claim.
    let response = claim_initial_admin(
        bound,
        Json(claim_request(
            TOKEN,
            "deploy-abc123",
            "Admin@Example.COM",
            "correct horse battery staple".to_owned(),
        )),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    fs::remove_file(token_path).unwrap();
}

#[actix_web::test]
async fn valid_claim_fails_closed_and_remains_retryable_when_persistence_is_unavailable() {
    let token_path = std::env::temp_dir().join(format!(
        "nazoauth-bootstrap-persistence-failure-{}",
        rand::random::<u64>()
    ));
    fs::write(&token_path, TOKEN).unwrap();
    let endpoint = Data::new(endpoint(Some(hash_token(TOKEN)), token_path.clone()));

    let response = claim_initial_admin(
        endpoint.clone(),
        Json(claim_request(
            TOKEN,
            DEPLOYMENT_ID,
            "Admin@Example.COM",
            "correct horse battery staple".to_owned(),
        )),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(endpoint.expected_token_hash(), Some(hash_token(TOKEN)));
    assert!(token_path.exists());
    fs::remove_file(token_path).unwrap();
}

#[actix_web::test]
async fn initialization_persists_a_retryable_token_before_database_ownership_is_requested() {
    let root = std::env::temp_dir().join(format!(
        "nazoauth-bootstrap-initialize-failure-{}",
        rand::random::<u64>()
    ));
    fs::create_dir(&root).unwrap();
    let pool = nazo_postgres::create_pool(
        "postgresql://unused:unused@127.0.0.1:1/unused?connect_timeout=1",
        1,
    )
    .unwrap();

    let error = match InitialAdminBootstrapEndpoint::initialize(
        pool,
        &root,
        "https://auth.example",
        "deploy-abc123",
        nazo_identity::TenantContext::default_system(),
    )
    .await
    {
        Ok(_) => panic!("unavailable persistence must not initialize bootstrap ownership"),
        Err(error) => error,
    };

    let token_path = root.join("bootstrap/initial-admin-token");
    let token = fs::read_to_string(&token_path).unwrap();
    assert!(valid_initial_admin_token(token.trim()));
    assert!(!error.to_string().contains(token.trim()));
    fs::remove_dir_all(root).unwrap();
}

#[actix_web::test]
async fn error_body_and_consumed_token_cleanup_are_stable() {
    let response = bootstrap_error(StatusCode::CONFLICT, "email_conflict");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = to_bytes(response.into_body()).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        json!({"error": "email_conflict"})
    );

    let token_path = std::env::temp_dir().join(format!(
        "nazoauth-consumed-token-test-{}",
        rand::random::<u64>()
    ));
    fs::write(&token_path, "secret").unwrap();
    remove_consumed_token(&token_path);
    assert!(!token_path.exists());
    remove_consumed_token(&token_path);

    let directory_path = std::env::temp_dir().join(format!(
        "nazoauth-consumed-token-directory-test-{}",
        rand::random::<u64>()
    ));
    fs::create_dir(&directory_path).unwrap();
    remove_consumed_token(&directory_path);
    assert!(directory_path.is_dir());
    fs::remove_dir(directory_path).unwrap();
}

#[test]
fn repository_bootstrap_states_control_token_lifetime() {
    let root = std::env::temp_dir().join(format!(
        "nazoauth-bootstrap-state-test-{}",
        rand::random::<u64>()
    ));
    fs::create_dir(&root).unwrap();
    let ready_path = root.join("ready");
    fs::write(&ready_path, "token").unwrap();
    assert_eq!(
        bootstrap_token_state(
            nazo_postgres::InitialAdminBootstrapState::Ready,
            &ready_path,
            "https://auth.example/",
            "hash".to_owned(),
        ),
        Some("hash".to_owned())
    );
    assert!(ready_path.exists());

    let claimed_path = root.join("claimed");
    fs::write(&claimed_path, "new-token").unwrap();
    assert_eq!(
        bootstrap_token_state(
            nazo_postgres::InitialAdminBootstrapState::Claimed {
                expected_token_hash: "persisted-hash".to_owned(),
            },
            &claimed_path,
            "https://auth.example/",
            "new-hash".to_owned(),
        ),
        Some("persisted-hash".to_owned())
    );
    assert!(!claimed_path.exists());

    let closed_path = root.join("closed");
    fs::write(&closed_path, "token").unwrap();
    assert_eq!(
        bootstrap_token_state(
            nazo_postgres::InitialAdminBootstrapState::Closed,
            &closed_path,
            "https://auth.example",
            "hash".to_owned(),
        ),
        None
    );
    assert!(!closed_path.exists());
    fs::remove_dir_all(root).unwrap();
}

#[actix_web::test]
async fn repository_claim_outcomes_have_closed_http_transitions() {
    let root = std::env::temp_dir().join(format!(
        "nazoauth-bootstrap-outcome-test-{}",
        rand::random::<u64>()
    ));
    fs::create_dir(&root).unwrap();

    let created_path = root.join("created");
    fs::write(&created_path, "token").unwrap();
    let created = endpoint(Some("hash".to_owned()), created_path.clone());
    let id = uuid::Uuid::now_v7();
    let response = claim_outcome_response(
        &created,
        nazo_postgres::InitialAdminClaimOutcome::Created {
            request_id: "bootstrap-admin-0123456789abcdef0123456789abcdef".to_owned(),
            id,
            email: "admin@example.com".to_owned(),
        },
    );
    assert_eq!(response.status(), StatusCode::CREATED);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap();
    assert_eq!(body["id"], id.to_string());
    assert_eq!(
        body["request_id"],
        "bootstrap-admin-0123456789abcdef0123456789abcdef"
    );
    assert_eq!(body["role"], "admin");
    assert_eq!(created.expected_token_hash().as_deref(), Some("hash"));
    assert!(created_path.exists());

    for (name, outcome, status) in [
        (
            "closed",
            nazo_postgres::InitialAdminClaimOutcome::Closed,
            StatusCode::GONE,
        ),
        (
            "conflict",
            nazo_postgres::InitialAdminClaimOutcome::EmailConflict,
            StatusCode::CONFLICT,
        ),
        (
            "request-conflict",
            nazo_postgres::InitialAdminClaimOutcome::IdempotencyConflict,
            StatusCode::CONFLICT,
        ),
    ] {
        let path = root.join(name);
        fs::write(&path, "token").unwrap();
        let endpoint = endpoint(Some("hash".to_owned()), path.clone());
        let response = claim_outcome_response(&endpoint, outcome);
        assert_eq!(response.status(), status);
        if status == StatusCode::GONE {
            assert!(endpoint.expected_token_hash().is_none());
            assert!(!path.exists());
        } else {
            assert!(endpoint.expected_token_hash().is_some());
            assert!(path.exists());
        }
    }
    fs::remove_dir_all(root).unwrap();
}
