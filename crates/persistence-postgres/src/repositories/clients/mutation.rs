use diesel::{ExpressionMethods, QueryDsl, QueryableByName, SelectableHelper, sql_query};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_auth::OAuthClient;
use nazo_identity::ports::RepositoryError;
use uuid::Uuid;

use crate::schema::{oauth_clients, oauth_tokens, user_client_grants};

use super::base::OAuthClientRepository;
use super::{OAuthClientRecord, bind_conformance_lease, conformance_lease_is_effective, map_error};

impl OAuthClientRepository {
    pub async fn insert(
        &self,
        client: &OAuthClient,
        client_secret_hash: Option<&str>,
        registration_access_token_blake3: Option<&str>,
        conformance_lease_id: Option<Uuid>,
    ) -> Result<OAuthClient, RepositoryError> {
        let mut connection = self.connection().await?;
        let record = connection
            .transaction::<OAuthClientRecord, diesel::result::Error, _>(async move |connection| {
                if let Some(conformance_lease_id) = conformance_lease_id {
                    // DCR is a lease-owned mutation.  Lock the lease row for
                    // the entire insert transaction so revocation and
                    // registration have one database linearization point:
                    // whichever operation acquires this row lock first wins.
                    // A pre-check followed by INSERT would allow a revoked
                    // lease to create a client in the interleaving window.
                    let locked = sql_query(
                        "SELECT id FROM conformance_leases \
                         WHERE tenant_id = $1 AND id = $2 \
                           AND expires_at > CURRENT_TIMESTAMP \
                           AND revoked_at IS NULL AND cleaned_at IS NULL \
                         FOR UPDATE",
                    )
                    .bind::<diesel::sql_types::Uuid, _>(client.tenant_id)
                    .bind::<diesel::sql_types::Uuid, _>(conformance_lease_id)
                    .get_result::<ActiveConformanceLease>(connection)
                    .await?;
                    debug_assert_eq!(locked.id, conformance_lease_id);
                }
                let record = diesel::insert_into(oauth_clients::table)
                    .values((
                        oauth_clients::id.eq(client.id),
                        oauth_clients::tenant_id.eq(client.tenant_id),
                        oauth_clients::realm_id.eq(client.realm_id),
                        oauth_clients::organization_id.eq(client.organization_id),
                        oauth_clients::client_id.eq(&client.client_id),
                        oauth_clients::client_name.eq(&client.client_name),
                        oauth_clients::client_type.eq(&client.client_type),
                        oauth_clients::client_secret_hash.eq(client_secret_hash),
                        oauth_clients::registration_access_token_blake3
                            .eq(registration_access_token_blake3),
                        oauth_clients::redirect_uris.eq(serde_json::json!(&client.redirect_uris)),
                        oauth_clients::post_logout_redirect_uris
                            .eq(serde_json::json!(&client.post_logout_redirect_uris)),
                        oauth_clients::scopes.eq(serde_json::json!(&client.scopes)),
                        oauth_clients::allowed_audiences
                            .eq(serde_json::json!(&client.allowed_audiences)),
                        oauth_clients::grant_types.eq(serde_json::json!(&client.grant_types)),
                        oauth_clients::token_endpoint_auth_method
                            .eq(&client.token_endpoint_auth_method),
                        oauth_clients::subject_type.eq(&client.subject_type),
                        oauth_clients::sector_identifier_uri.eq(&client.sector_identifier_uri),
                        oauth_clients::sector_identifier_host.eq(&client.sector_identifier_host),
                        oauth_clients::require_dpop_bound_tokens
                            .eq(client.require_dpop_bound_tokens),
                        oauth_clients::require_mtls_bound_tokens
                            .eq(client.require_mtls_bound_tokens),
                        oauth_clients::allow_client_assertion_audience_array
                            .eq(client.allow_client_assertion_audience_array),
                        oauth_clients::allow_client_assertion_endpoint_audience
                            .eq(client.allow_client_assertion_endpoint_audience),
                        oauth_clients::require_par_request_object
                            .eq(client.require_par_request_object),
                        oauth_clients::backchannel_logout_uri.eq(&client.backchannel_logout_uri),
                        oauth_clients::backchannel_logout_session_required
                            .eq(client.backchannel_logout_session_required),
                        oauth_clients::backchannel_token_delivery_mode
                            .eq(&client.backchannel_token_delivery_mode),
                        oauth_clients::backchannel_client_notification_endpoint
                            .eq(&client.backchannel_client_notification_endpoint),
                        oauth_clients::backchannel_authentication_request_signing_alg
                            .eq(&client.backchannel_authentication_request_signing_alg),
                        oauth_clients::backchannel_user_code_parameter
                            .eq(client.backchannel_user_code_parameter),
                        oauth_clients::frontchannel_logout_uri.eq(&client.frontchannel_logout_uri),
                        oauth_clients::frontchannel_logout_session_required
                            .eq(client.frontchannel_logout_session_required),
                        oauth_clients::tls_client_auth_subject_dn
                            .eq(&client.tls_client_auth_subject_dn),
                        oauth_clients::tls_client_auth_cert_sha256
                            .eq(&client.tls_client_auth_cert_sha256),
                        oauth_clients::tls_client_auth_san_dns
                            .eq(serde_json::json!(&client.tls_client_auth_san_dns)),
                        oauth_clients::tls_client_auth_san_uri
                            .eq(serde_json::json!(&client.tls_client_auth_san_uri)),
                        oauth_clients::tls_client_auth_san_ip
                            .eq(serde_json::json!(&client.tls_client_auth_san_ip)),
                        oauth_clients::tls_client_auth_san_email
                            .eq(serde_json::json!(&client.tls_client_auth_san_email)),
                        oauth_clients::jwks_uri.eq(&client.jwks_uri),
                        oauth_clients::jwks.eq(&client.jwks),
                        oauth_clients::request_uris.eq(serde_json::json!(&client.request_uris)),
                        oauth_clients::initiate_login_uri.eq(&client.initiate_login_uri),
                        oauth_clients::logo_uri.eq(&client.presentation.logo_uri),
                        oauth_clients::policy_uri.eq(&client.presentation.policy_uri),
                        oauth_clients::tos_uri.eq(&client.presentation.tos_uri),
                        oauth_clients::id_token_signed_response_alg
                            .eq(&client.id_token_signed_response_alg),
                        oauth_clients::id_token_encrypted_response_alg
                            .eq(&client.id_token_encrypted_response_alg),
                        oauth_clients::id_token_encrypted_response_enc
                            .eq(&client.id_token_encrypted_response_enc),
                        oauth_clients::request_object_signing_alg
                            .eq(&client.request_object_signing_alg),
                        oauth_clients::request_object_encryption_alg
                            .eq(&client.request_object_encryption_alg),
                        oauth_clients::request_object_encryption_enc
                            .eq(&client.request_object_encryption_enc),
                        oauth_clients::token_endpoint_auth_signing_alg
                            .eq(&client.token_endpoint_auth_signing_alg),
                        oauth_clients::introspection_signed_response_alg
                            .eq(&client.introspection_signed_response_alg),
                        oauth_clients::introspection_encrypted_response_alg
                            .eq(&client.introspection_encrypted_response_alg),
                        oauth_clients::introspection_encrypted_response_enc
                            .eq(&client.introspection_encrypted_response_enc),
                        oauth_clients::userinfo_signed_response_alg
                            .eq(&client.userinfo_signed_response_alg),
                        oauth_clients::userinfo_encrypted_response_alg
                            .eq(&client.userinfo_encrypted_response_alg),
                        oauth_clients::userinfo_encrypted_response_enc
                            .eq(&client.userinfo_encrypted_response_enc),
                        oauth_clients::authorization_signed_response_alg
                            .eq(&client.authorization_signed_response_alg),
                        oauth_clients::authorization_encrypted_response_alg
                            .eq(&client.authorization_encrypted_response_alg),
                        oauth_clients::authorization_encrypted_response_enc
                            .eq(&client.authorization_encrypted_response_enc),
                        oauth_clients::security_policy.eq(client
                            .security_policy
                            .as_ref()
                            .map(|policy| serde_json::json!(policy))),
                        oauth_clients::is_active.eq(client.is_active),
                    ))
                    .returning(OAuthClientRecord::as_returning())
                    .get_result::<OAuthClientRecord>(connection)
                    .await?;
                bind_conformance_lease(connection, client.id, conformance_lease_id).await?;
                Ok(record)
            })
            .await
            .map_err(map_error)?;
        record.into_domain()
    }

    pub async fn upsert(
        &self,
        client: &OAuthClient,
        client_secret_hash: Option<&str>,
    ) -> Result<(), RepositoryError> {
        let mut connection = self.connection().await?;
        upsert_client_on_connection(&mut connection, client, client_secret_hash)
            .await
            .map_err(map_error)
    }

    pub async fn update_metadata(
        &self,
        client: &OAuthClient,
    ) -> Result<OAuthClient, RepositoryError> {
        self.replace(client, None).await
    }

    async fn replace(
        &self,
        client: &OAuthClient,
        credentials: Option<(Option<&str>, Option<&str>)>,
    ) -> Result<OAuthClient, RepositoryError> {
        let mut connection = self.connection().await?;
        let target = oauth_clients::table
            .filter(oauth_clients::tenant_id.eq(client.tenant_id))
            .filter(oauth_clients::id.eq(client.id));
        let metadata = (
            oauth_clients::client_name.eq(&client.client_name),
            oauth_clients::client_type.eq(&client.client_type),
            oauth_clients::redirect_uris.eq(serde_json::json!(&client.redirect_uris)),
            oauth_clients::post_logout_redirect_uris
                .eq(serde_json::json!(&client.post_logout_redirect_uris)),
            oauth_clients::scopes.eq(serde_json::json!(&client.scopes)),
            oauth_clients::allowed_audiences.eq(serde_json::json!(&client.allowed_audiences)),
            oauth_clients::grant_types.eq(serde_json::json!(&client.grant_types)),
            oauth_clients::token_endpoint_auth_method.eq(&client.token_endpoint_auth_method),
            oauth_clients::subject_type.eq(&client.subject_type),
            oauth_clients::sector_identifier_uri.eq(&client.sector_identifier_uri),
            oauth_clients::sector_identifier_host.eq(&client.sector_identifier_host),
            oauth_clients::require_dpop_bound_tokens.eq(client.require_dpop_bound_tokens),
            oauth_clients::require_mtls_bound_tokens.eq(client.require_mtls_bound_tokens),
            oauth_clients::allow_client_assertion_audience_array
                .eq(client.allow_client_assertion_audience_array),
            oauth_clients::allow_client_assertion_endpoint_audience
                .eq(client.allow_client_assertion_endpoint_audience),
            oauth_clients::require_par_request_object.eq(client.require_par_request_object),
            oauth_clients::backchannel_logout_uri.eq(&client.backchannel_logout_uri),
            oauth_clients::backchannel_logout_session_required
                .eq(client.backchannel_logout_session_required),
            oauth_clients::backchannel_token_delivery_mode
                .eq(&client.backchannel_token_delivery_mode),
            oauth_clients::backchannel_client_notification_endpoint
                .eq(&client.backchannel_client_notification_endpoint),
            oauth_clients::backchannel_authentication_request_signing_alg
                .eq(&client.backchannel_authentication_request_signing_alg),
            oauth_clients::backchannel_user_code_parameter
                .eq(client.backchannel_user_code_parameter),
            oauth_clients::frontchannel_logout_uri.eq(&client.frontchannel_logout_uri),
            oauth_clients::frontchannel_logout_session_required
                .eq(client.frontchannel_logout_session_required),
            oauth_clients::tls_client_auth_subject_dn.eq(&client.tls_client_auth_subject_dn),
            oauth_clients::tls_client_auth_cert_sha256.eq(&client.tls_client_auth_cert_sha256),
            oauth_clients::tls_client_auth_san_dns
                .eq(serde_json::json!(&client.tls_client_auth_san_dns)),
            oauth_clients::tls_client_auth_san_uri
                .eq(serde_json::json!(&client.tls_client_auth_san_uri)),
            oauth_clients::tls_client_auth_san_ip
                .eq(serde_json::json!(&client.tls_client_auth_san_ip)),
            oauth_clients::tls_client_auth_san_email
                .eq(serde_json::json!(&client.tls_client_auth_san_email)),
            oauth_clients::jwks_uri.eq(&client.jwks_uri),
            oauth_clients::jwks.eq(&client.jwks),
            oauth_clients::request_uris.eq(serde_json::json!(&client.request_uris)),
            oauth_clients::initiate_login_uri.eq(&client.initiate_login_uri),
            oauth_clients::logo_uri.eq(&client.presentation.logo_uri),
            oauth_clients::policy_uri.eq(&client.presentation.policy_uri),
            oauth_clients::tos_uri.eq(&client.presentation.tos_uri),
            oauth_clients::id_token_signed_response_alg.eq(&client.id_token_signed_response_alg),
            oauth_clients::id_token_encrypted_response_alg
                .eq(&client.id_token_encrypted_response_alg),
            oauth_clients::id_token_encrypted_response_enc
                .eq(&client.id_token_encrypted_response_enc),
            oauth_clients::request_object_signing_alg.eq(&client.request_object_signing_alg),
            oauth_clients::request_object_encryption_alg.eq(&client.request_object_encryption_alg),
            oauth_clients::request_object_encryption_enc.eq(&client.request_object_encryption_enc),
            oauth_clients::token_endpoint_auth_signing_alg
                .eq(&client.token_endpoint_auth_signing_alg),
            oauth_clients::introspection_signed_response_alg
                .eq(&client.introspection_signed_response_alg),
            oauth_clients::introspection_encrypted_response_alg
                .eq(&client.introspection_encrypted_response_alg),
            oauth_clients::introspection_encrypted_response_enc
                .eq(&client.introspection_encrypted_response_enc),
            oauth_clients::userinfo_signed_response_alg.eq(&client.userinfo_signed_response_alg),
            oauth_clients::userinfo_encrypted_response_alg
                .eq(&client.userinfo_encrypted_response_alg),
            oauth_clients::userinfo_encrypted_response_enc
                .eq(&client.userinfo_encrypted_response_enc),
            oauth_clients::authorization_signed_response_alg
                .eq(&client.authorization_signed_response_alg),
            oauth_clients::authorization_encrypted_response_alg
                .eq(&client.authorization_encrypted_response_alg),
            oauth_clients::authorization_encrypted_response_enc
                .eq(&client.authorization_encrypted_response_enc),
            oauth_clients::security_policy.eq(client
                .security_policy
                .as_ref()
                .map(|policy| serde_json::json!(policy))),
            oauth_clients::is_active.eq(client.is_active),
            oauth_clients::updated_at.eq(diesel::dsl::now),
        );
        let record = if let Some((secret_hash, access_token_hash)) = credentials {
            diesel::update(target)
                .set((
                    metadata,
                    oauth_clients::client_secret_hash.eq(secret_hash),
                    oauth_clients::registration_access_token_blake3.eq(access_token_hash),
                ))
                .returning(OAuthClientRecord::as_returning())
                .get_result::<OAuthClientRecord>(&mut connection)
                .await
        } else {
            diesel::update(target)
                .set(metadata)
                .returning(OAuthClientRecord::as_returning())
                .get_result::<OAuthClientRecord>(&mut connection)
                .await
        }
        .map_err(map_error)?;
        record.into_domain()
    }

    pub async fn replace_registration(
        &self,
        client: &OAuthClient,
        client_secret_hash: Option<&str>,
        expected_registration_access_token_blake3: &str,
        new_registration_access_token_blake3: Option<&str>,
    ) -> Result<OAuthClient, RepositoryError> {
        let mut connection = self.connection().await?;
        let mut metadata = serde_json::json!({
            "client_name": client.client_name,
            "client_type": client.client_type,
            "redirect_uris": client.redirect_uris,
            "post_logout_redirect_uris": client.post_logout_redirect_uris,
            "scopes": client.scopes,
            "allowed_audiences": client.allowed_audiences,
            "grant_types": client.grant_types,
            "token_endpoint_auth_method": client.token_endpoint_auth_method,
            "subject_type": client.subject_type,
            "sector_identifier_uri": client.sector_identifier_uri,
            "sector_identifier_host": client.sector_identifier_host,
            "require_dpop_bound_tokens": client.require_dpop_bound_tokens,
            "require_mtls_bound_tokens": client.require_mtls_bound_tokens,
            "allow_client_assertion_audience_array": client.allow_client_assertion_audience_array,
            "allow_client_assertion_endpoint_audience": client.allow_client_assertion_endpoint_audience,
            "require_par_request_object": client.require_par_request_object,
            "backchannel_logout_uri": client.backchannel_logout_uri,
            "backchannel_logout_session_required": client.backchannel_logout_session_required,
            "frontchannel_logout_uri": client.frontchannel_logout_uri,
            "frontchannel_logout_session_required": client.frontchannel_logout_session_required,
            "tls_client_auth_subject_dn": client.tls_client_auth_subject_dn,
            "tls_client_auth_cert_sha256": client.tls_client_auth_cert_sha256,
            "tls_client_auth_san_dns": client.tls_client_auth_san_dns,
            "tls_client_auth_san_uri": client.tls_client_auth_san_uri,
            "tls_client_auth_san_ip": client.tls_client_auth_san_ip,
            "tls_client_auth_san_email": client.tls_client_auth_san_email,
            "jwks_uri": client.jwks_uri,
            "jwks": client.jwks,
            "request_uris": client.request_uris,
            "initiate_login_uri": client.initiate_login_uri,
            "logo_uri": client.presentation.logo_uri,
            "policy_uri": client.presentation.policy_uri,
            "tos_uri": client.presentation.tos_uri,
            "introspection_encrypted_response_alg": client.introspection_encrypted_response_alg,
            "introspection_encrypted_response_enc": client.introspection_encrypted_response_enc,
            "userinfo_signed_response_alg": client.userinfo_signed_response_alg,
            "userinfo_encrypted_response_alg": client.userinfo_encrypted_response_alg,
            "userinfo_encrypted_response_enc": client.userinfo_encrypted_response_enc,
            "authorization_signed_response_alg": client.authorization_signed_response_alg,
            "authorization_encrypted_response_alg": client.authorization_encrypted_response_alg,
            "authorization_encrypted_response_enc": client.authorization_encrypted_response_enc,
        });
        let metadata_object = metadata
            .as_object_mut()
            .expect("client replacement metadata is always a JSON object");
        for (field, value) in [
            (
                "id_token_signed_response_alg",
                &client.id_token_signed_response_alg,
            ),
            (
                "id_token_encrypted_response_alg",
                &client.id_token_encrypted_response_alg,
            ),
            (
                "id_token_encrypted_response_enc",
                &client.id_token_encrypted_response_enc,
            ),
            (
                "request_object_signing_alg",
                &client.request_object_signing_alg,
            ),
            (
                "request_object_encryption_alg",
                &client.request_object_encryption_alg,
            ),
            (
                "request_object_encryption_enc",
                &client.request_object_encryption_enc,
            ),
            (
                "token_endpoint_auth_signing_alg",
                &client.token_endpoint_auth_signing_alg,
            ),
            (
                "introspection_signed_response_alg",
                &client.introspection_signed_response_alg,
            ),
        ] {
            metadata_object.insert(field.to_owned(), serde_json::json!(value));
        }
        metadata_object.insert(
            "backchannel_token_delivery_mode".to_owned(),
            serde_json::json!(client.backchannel_token_delivery_mode),
        );
        metadata_object.insert(
            "backchannel_client_notification_endpoint".to_owned(),
            serde_json::json!(client.backchannel_client_notification_endpoint),
        );
        metadata_object.insert(
            "backchannel_authentication_request_signing_alg".to_owned(),
            serde_json::json!(client.backchannel_authentication_request_signing_alg),
        );
        metadata_object.insert(
            "backchannel_user_code_parameter".to_owned(),
            serde_json::json!(client.backchannel_user_code_parameter),
        );
        metadata_object.insert(
            "security_policy".to_owned(),
            serde_json::json!(client.security_policy),
        );
        let record = connection
            .transaction::<OAuthClientRecord, diesel::result::Error, _>(async move |connection| {
                let changed = diesel::sql_query(
                    r#"
            UPDATE oauth_clients SET
                client_name = $3->>'client_name',
                client_type = $3->>'client_type',
                client_secret_hash = $4,
                registration_access_token_blake3 = $5,
                redirect_uris = $3->'redirect_uris',
                post_logout_redirect_uris = $3->'post_logout_redirect_uris',
                scopes = $3->'scopes', allowed_audiences = $3->'allowed_audiences',
                grant_types = $3->'grant_types',
                token_endpoint_auth_method = $3->>'token_endpoint_auth_method',
                subject_type = $3->>'subject_type',
                sector_identifier_uri = $3->>'sector_identifier_uri',
                sector_identifier_host = $3->>'sector_identifier_host',
                require_dpop_bound_tokens = ($3->>'require_dpop_bound_tokens')::boolean,
                require_mtls_bound_tokens = ($3->>'require_mtls_bound_tokens')::boolean,
                allow_client_assertion_audience_array = ($3->>'allow_client_assertion_audience_array')::boolean,
                allow_client_assertion_endpoint_audience = ($3->>'allow_client_assertion_endpoint_audience')::boolean,
                require_par_request_object = ($3->>'require_par_request_object')::boolean,
                backchannel_logout_uri = $3->>'backchannel_logout_uri',
                backchannel_logout_session_required = ($3->>'backchannel_logout_session_required')::boolean,
                backchannel_token_delivery_mode = $3->>'backchannel_token_delivery_mode',
                backchannel_client_notification_endpoint = $3->>'backchannel_client_notification_endpoint',
                backchannel_authentication_request_signing_alg = $3->>'backchannel_authentication_request_signing_alg',
                backchannel_user_code_parameter = ($3->>'backchannel_user_code_parameter')::boolean,
                frontchannel_logout_uri = $3->>'frontchannel_logout_uri',
                frontchannel_logout_session_required = ($3->>'frontchannel_logout_session_required')::boolean,
                tls_client_auth_subject_dn = $3->>'tls_client_auth_subject_dn',
                tls_client_auth_cert_sha256 = $3->>'tls_client_auth_cert_sha256',
                tls_client_auth_san_dns = $3->'tls_client_auth_san_dns',
                tls_client_auth_san_uri = $3->'tls_client_auth_san_uri',
                tls_client_auth_san_ip = $3->'tls_client_auth_san_ip',
                tls_client_auth_san_email = $3->'tls_client_auth_san_email',
                jwks_uri = $3->>'jwks_uri',
                jwks = NULLIF($3->'jwks', 'null'::jsonb),
                request_uris = $3->'request_uris',
                initiate_login_uri = $3->>'initiate_login_uri',
                logo_uri = $3->>'logo_uri',
                policy_uri = $3->>'policy_uri',
                tos_uri = $3->>'tos_uri',
                id_token_signed_response_alg = $3->>'id_token_signed_response_alg',
                id_token_encrypted_response_alg = $3->>'id_token_encrypted_response_alg',
                id_token_encrypted_response_enc = $3->>'id_token_encrypted_response_enc',
                request_object_signing_alg = $3->>'request_object_signing_alg',
                request_object_encryption_alg = $3->>'request_object_encryption_alg',
                request_object_encryption_enc = $3->>'request_object_encryption_enc',
                token_endpoint_auth_signing_alg = $3->>'token_endpoint_auth_signing_alg',
                introspection_signed_response_alg = $3->>'introspection_signed_response_alg',
                introspection_encrypted_response_alg = $3->>'introspection_encrypted_response_alg',
                introspection_encrypted_response_enc = $3->>'introspection_encrypted_response_enc',
                userinfo_signed_response_alg = $3->>'userinfo_signed_response_alg',
                userinfo_encrypted_response_alg = $3->>'userinfo_encrypted_response_alg',
                userinfo_encrypted_response_enc = $3->>'userinfo_encrypted_response_enc',
                authorization_signed_response_alg = $3->>'authorization_signed_response_alg',
                authorization_encrypted_response_alg = $3->>'authorization_encrypted_response_alg',
                authorization_encrypted_response_enc = $3->>'authorization_encrypted_response_enc',
                security_policy = NULLIF($3->'security_policy', 'null'::jsonb),
                updated_at = CURRENT_TIMESTAMP
            WHERE tenant_id = $1 AND id = $2 AND is_active = TRUE
              AND nazo_oauth_conformance_lease_is_active(
                  tenant_id, conformance_lease_id
              )
              AND registration_access_token_blake3 = $6
            "#,
                )
                .bind::<diesel::sql_types::Uuid, _>(client.tenant_id)
                .bind::<diesel::sql_types::Uuid, _>(client.id)
                .bind::<diesel::sql_types::Jsonb, _>(&metadata)
                .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(
                    client_secret_hash,
                )
                .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(
                    new_registration_access_token_blake3,
                )
                .bind::<diesel::sql_types::VarChar, _>(
                    expected_registration_access_token_blake3,
                )
                .execute(connection)
                .await?;
                if changed != 1 {
                    return Err(diesel::result::Error::NotFound);
                }
                oauth_clients::table
                    .filter(oauth_clients::tenant_id.eq(client.tenant_id))
                    .filter(oauth_clients::id.eq(client.id))
                    .select(OAuthClientRecord::as_select())
                    .first::<OAuthClientRecord>(connection)
                    .await
            })
            .await
            .map_err(map_error)?;
        record.into_domain()
    }

    pub async fn rotate_credentials(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        client_secret_hash: Option<&str>,
        expected_registration_access_token_blake3: &str,
        new_registration_access_token_blake3: &str,
    ) -> Result<OAuthClient, RepositoryError> {
        let mut connection = self.connection().await?;
        diesel::update(
            oauth_clients::table
                .filter(oauth_clients::tenant_id.eq(tenant_id))
                .filter(oauth_clients::id.eq(id))
                .filter(oauth_clients::is_active.eq(true))
                .filter(conformance_lease_is_effective())
                .filter(
                    oauth_clients::registration_access_token_blake3
                        .eq(expected_registration_access_token_blake3),
                ),
        )
        .set((
            oauth_clients::registration_access_token_blake3
                .eq(Some(new_registration_access_token_blake3)),
            oauth_clients::client_secret_hash.eq(client_secret_hash),
            oauth_clients::updated_at.eq(diesel::dsl::now),
        ))
        .returning(OAuthClientRecord::as_returning())
        .get_result::<OAuthClientRecord>(&mut connection)
        .await
        .map_err(map_error)?
        .into_domain()
    }

    pub async fn deactivate(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        expected_registration_access_token_blake3: &str,
    ) -> Result<bool, RepositoryError> {
        let mut connection = self.connection().await?;
        connection
            .transaction::<bool, diesel::result::Error, _>(async |connection| {
                let changed = diesel::update(
                    oauth_clients::table
                        .filter(oauth_clients::tenant_id.eq(tenant_id))
                        .filter(oauth_clients::id.eq(id))
                        .filter(oauth_clients::is_active.eq(true))
                        .filter(conformance_lease_is_effective())
                        .filter(
                            oauth_clients::registration_access_token_blake3
                                .eq(expected_registration_access_token_blake3),
                        ),
                )
                .set((
                    oauth_clients::is_active.eq(false),
                    oauth_clients::registration_access_token_blake3.eq::<Option<String>>(None),
                    oauth_clients::updated_at.eq(diesel::dsl::now),
                ))
                .execute(connection)
                .await?;
                if changed != 1 {
                    return Err(diesel::result::Error::NotFound);
                }
                diesel::update(
                    oauth_tokens::table
                        .filter(oauth_tokens::tenant_id.eq(tenant_id))
                        .filter(oauth_tokens::client_id.eq(id))
                        .filter(oauth_tokens::revoked_at.is_null()),
                )
                .set(oauth_tokens::revoked_at.eq(diesel::dsl::now))
                .execute(connection)
                .await?;
                diesel::delete(
                    user_client_grants::table
                        .filter(user_client_grants::tenant_id.eq(tenant_id))
                        .filter(user_client_grants::client_id.eq(id)),
                )
                .execute(connection)
                .await?;
                Ok(true)
            })
            .await
            .map_err(map_error)
    }
}

#[derive(QueryableByName)]
struct ActiveConformanceLease {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    id: Uuid,
}

pub(crate) async fn upsert_client_on_connection(
    connection: &mut AsyncPgConnection,
    client: &OAuthClient,
    client_secret_hash: Option<&str>,
) -> diesel::QueryResult<()> {
    let redirect_uris = serde_json::json!(&client.redirect_uris);
    let post_logout_redirect_uris = serde_json::json!(&client.post_logout_redirect_uris);
    let scopes = serde_json::json!(&client.scopes);
    let allowed_audiences = serde_json::json!(&client.allowed_audiences);
    let grant_types = serde_json::json!(&client.grant_types);
    diesel::sql_query(
        r#"
        INSERT INTO oauth_clients (
            tenant_id, realm_id, organization_id, client_id, client_name, client_type,
            client_secret_hash, redirect_uris, post_logout_redirect_uris, scopes,
            allowed_audiences, grant_types, token_endpoint_auth_method,
            require_dpop_bound_tokens, require_mtls_bound_tokens,
            tls_client_auth_subject_dn, tls_client_auth_cert_sha256,
            allow_client_assertion_audience_array,
            allow_client_assertion_endpoint_audience, require_par_request_object,
            backchannel_token_delivery_mode, backchannel_client_notification_endpoint,
            backchannel_authentication_request_signing_alg, backchannel_user_code_parameter,
            frontchannel_logout_uri,
            frontchannel_logout_session_required, jwks,
            authorization_signed_response_alg,
            id_token_signed_response_alg, id_token_encrypted_response_alg,
            id_token_encrypted_response_enc, request_object_signing_alg,
            request_object_encryption_alg, request_object_encryption_enc,
            token_endpoint_auth_signing_alg, introspection_signed_response_alg,
            security_policy, is_active
        ) VALUES (
            $1, $2, $3, $4, $5, 'confidential', $6, $7, $8, $9, $10, $11, $12,
            $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26,
            $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, TRUE
        )
        ON CONFLICT (tenant_id, client_id) DO UPDATE SET
            client_name = EXCLUDED.client_name,
            client_type = EXCLUDED.client_type,
            client_secret_hash = EXCLUDED.client_secret_hash,
            redirect_uris = EXCLUDED.redirect_uris,
            post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
            scopes = EXCLUDED.scopes,
            allowed_audiences = EXCLUDED.allowed_audiences,
            grant_types = EXCLUDED.grant_types,
            token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method,
            require_dpop_bound_tokens = EXCLUDED.require_dpop_bound_tokens,
            require_mtls_bound_tokens = EXCLUDED.require_mtls_bound_tokens,
            tls_client_auth_subject_dn = EXCLUDED.tls_client_auth_subject_dn,
            tls_client_auth_cert_sha256 = EXCLUDED.tls_client_auth_cert_sha256,
            allow_client_assertion_audience_array = EXCLUDED.allow_client_assertion_audience_array,
            allow_client_assertion_endpoint_audience = EXCLUDED.allow_client_assertion_endpoint_audience,
            require_par_request_object = EXCLUDED.require_par_request_object,
            backchannel_token_delivery_mode = EXCLUDED.backchannel_token_delivery_mode,
            backchannel_client_notification_endpoint = EXCLUDED.backchannel_client_notification_endpoint,
            backchannel_authentication_request_signing_alg = EXCLUDED.backchannel_authentication_request_signing_alg,
            backchannel_user_code_parameter = EXCLUDED.backchannel_user_code_parameter,
            frontchannel_logout_uri = EXCLUDED.frontchannel_logout_uri,
            frontchannel_logout_session_required = EXCLUDED.frontchannel_logout_session_required,
            jwks = EXCLUDED.jwks,
            authorization_signed_response_alg = EXCLUDED.authorization_signed_response_alg,
            id_token_signed_response_alg = EXCLUDED.id_token_signed_response_alg,
            id_token_encrypted_response_alg = EXCLUDED.id_token_encrypted_response_alg,
            id_token_encrypted_response_enc = EXCLUDED.id_token_encrypted_response_enc,
            request_object_signing_alg = EXCLUDED.request_object_signing_alg,
            request_object_encryption_alg = EXCLUDED.request_object_encryption_alg,
            request_object_encryption_enc = EXCLUDED.request_object_encryption_enc,
            token_endpoint_auth_signing_alg = EXCLUDED.token_endpoint_auth_signing_alg,
            introspection_signed_response_alg = EXCLUDED.introspection_signed_response_alg,
            security_policy = EXCLUDED.security_policy,
            is_active = TRUE,
            updated_at = CURRENT_TIMESTAMP
        "#,
    )
    .bind::<diesel::sql_types::Uuid, _>(client.tenant_id)
    .bind::<diesel::sql_types::Uuid, _>(client.realm_id)
    .bind::<diesel::sql_types::Uuid, _>(client.organization_id)
    .bind::<diesel::sql_types::VarChar, _>(&client.client_id)
    .bind::<diesel::sql_types::VarChar, _>(&client.client_name)
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(client_secret_hash)
    .bind::<diesel::sql_types::Jsonb, _>(&redirect_uris)
    .bind::<diesel::sql_types::Jsonb, _>(&post_logout_redirect_uris)
    .bind::<diesel::sql_types::Jsonb, _>(&scopes)
    .bind::<diesel::sql_types::Jsonb, _>(&allowed_audiences)
    .bind::<diesel::sql_types::Jsonb, _>(&grant_types)
    .bind::<diesel::sql_types::VarChar, _>(&client.token_endpoint_auth_method)
    .bind::<diesel::sql_types::Bool, _>(client.require_dpop_bound_tokens)
    .bind::<diesel::sql_types::Bool, _>(client.require_mtls_bound_tokens)
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(
        &client.tls_client_auth_subject_dn,
    )
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(
        &client.tls_client_auth_cert_sha256,
    )
    .bind::<diesel::sql_types::Bool, _>(client.allow_client_assertion_audience_array)
    .bind::<diesel::sql_types::Bool, _>(client.allow_client_assertion_endpoint_audience)
    .bind::<diesel::sql_types::Bool, _>(client.require_par_request_object)
    .bind::<diesel::sql_types::VarChar, _>(&client.backchannel_token_delivery_mode)
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(
        &client.backchannel_client_notification_endpoint,
    )
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(
        &client.backchannel_authentication_request_signing_alg,
    )
    .bind::<diesel::sql_types::Bool, _>(client.backchannel_user_code_parameter)
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(
        &client.frontchannel_logout_uri,
    )
    .bind::<diesel::sql_types::Bool, _>(client.frontchannel_logout_session_required)
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Jsonb>, _>(&client.jwks)
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(
        &client.authorization_signed_response_alg,
    )
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(
        &client.id_token_signed_response_alg,
    )
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(
        &client.id_token_encrypted_response_alg,
    )
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(
        &client.id_token_encrypted_response_enc,
    )
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(
        &client.request_object_signing_alg,
    )
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(
        &client.request_object_encryption_alg,
    )
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(
        &client.request_object_encryption_enc,
    )
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(
        &client.token_endpoint_auth_signing_alg,
    )
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(
        &client.introspection_signed_response_alg,
    )
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Jsonb>, _>(
        client
            .security_policy
            .as_ref()
            .map(|policy| serde_json::json!(policy)),
    )
    .execute(connection)
    .await
    .map(|_| ())
}
