use std::{
    fs,
    sync::{Arc, RwLock},
};

use actix_web::{body::to_bytes, web::Data};

use super::*;

fn endpoint(
    expected_token_hash: Option<String>,
    token_path: PathBuf,
) -> InitialAdminBootstrapEndpoint {
    let pool =
        nazo_postgres::create_pool("postgresql://unused:unused@127.0.0.1:1/unused", 1).unwrap();
    InitialAdminBootstrapEndpoint {
        repository: nazo_postgres::InitialAdminBootstrapRepository::new(pool),
        expected_token_hash: Arc::new(RwLock::new(expected_token_hash)),
        token_path,
    }
}

#[actix_web::test]
async fn setup_page_is_token_bound_escaped_and_referrer_safe() {
    let token = "<&\"'>";
    let endpoint = Data::new(endpoint(
        Some(hash_token(token)),
        PathBuf::from("unused-token"),
    ));
    let response = initial_admin_setup_page(
        endpoint.clone(),
        Query(SetupQuery {
            token: token.to_owned(),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::REFERRER_POLICY).unwrap(),
        "no-referrer"
    );
    let body = to_bytes(response.into_body()).await.unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.contains("&lt;&amp;&quot;&#39;&gt;"));
    assert!(!body.contains(token));

    let response = initial_admin_setup_page(
        endpoint,
        Query(SetupQuery {
            token: "wrong".to_owned(),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
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
        Form(InitialAdminClaimRequest {
            token: "token".to_owned(),
            email: "admin@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::GONE);

    let ready = Data::new(endpoint(Some(hash_token("token")), token_path.clone()));
    let response = claim_initial_admin(
        ready.clone(),
        Form(InitialAdminClaimRequest {
            token: "wrong".to_owned(),
            email: "admin@example.com".to_owned(),
            password: "correct horse battery staple".to_owned(),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let response = claim_initial_admin(
        ready.clone(),
        Form(InitialAdminClaimRequest {
            token: "token".to_owned(),
            email: "not-an-email".to_owned(),
            password: "correct horse battery staple".to_owned(),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    for password in ["short".to_owned(), "x".repeat(1025)] {
        let response = claim_initial_admin(
            ready.clone(),
            Form(InitialAdminClaimRequest {
                token: "token".to_owned(),
                email: "admin@example.com".to_owned(),
                password,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    ready.close();
    assert!(ready.expected_token_hash().is_none());
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
}

#[test]
fn repository_bootstrap_states_control_token_lifetime() {
    let root = std::env::temp_dir().join(format!(
        "nazoauth-bootstrap-state-test-{}",
        rand::random::<u64>()
    ));
    fs::create_dir(&root).unwrap();
    let expires_at = Utc::now() + Duration::minutes(5);

    let ready_path = root.join("ready");
    fs::write(&ready_path, "token").unwrap();
    assert_eq!(
        bootstrap_token_state(
            nazo_postgres::InitialAdminBootstrapState::Ready { expires_at },
            &ready_path,
            "https://auth.example/",
            "hash".to_owned(),
        ),
        Some("hash".to_owned())
    );
    assert!(ready_path.exists());

    for (name, state) in [
        ("closed", nazo_postgres::InitialAdminBootstrapState::Closed),
        (
            "owned",
            nazo_postgres::InitialAdminBootstrapState::OwnedByAnotherInstance { expires_at },
        ),
    ] {
        let path = root.join(name);
        fs::write(&path, "token").unwrap();
        assert_eq!(
            bootstrap_token_state(state, &path, "https://auth.example", "hash".to_owned()),
            None
        );
        assert!(!path.exists());
    }
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
            id,
            email: "admin@example.com".to_owned(),
        },
    );
    assert_eq!(response.status(), StatusCode::CREATED);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap();
    assert_eq!(body["id"], id.to_string());
    assert_eq!(body["role"], "admin");
    assert!(created.expected_token_hash().is_none());
    assert!(!created_path.exists());

    for (name, outcome, status) in [
        (
            "closed",
            nazo_postgres::InitialAdminClaimOutcome::Closed,
            StatusCode::GONE,
        ),
        (
            "expired",
            nazo_postgres::InitialAdminClaimOutcome::InvalidOrExpired,
            StatusCode::NOT_FOUND,
        ),
        (
            "conflict",
            nazo_postgres::InitialAdminClaimOutcome::EmailConflict,
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
