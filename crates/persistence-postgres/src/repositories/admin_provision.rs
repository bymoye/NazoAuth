use chrono::{DateTime, Utc};
use diesel::{
    ExpressionMethods, OptionalExtension, QueryDsl, Queryable, Selectable, SelectableHelper,
    sql_query, sql_types::BigInt,
};
use diesel_async::{AsyncConnection as _, RunQueryDsl as _};
use nazo_identity::{TenantContext, email::normalize_email_address};
use sha2::Digest as _;
use uuid::Uuid;

use crate::{
    DbPool, get_conn,
    schema::{admin_provision_receipts, identity_security_events, users},
};

const MAX_OPERATION_ID_BYTES: usize = 128;
const MAX_DEPLOYMENT_ID_BYTES: usize = 128;
const ADMIN_PROVISION_EVENT_TYPE: &str = "admin_user_created";
const ADMIN_PROVISION_REASON: &str = "admin_created";

#[derive(Clone, Debug)]
pub struct AdminProvisionRequest {
    pub tenant: TenantContext,
    pub operation_id: String,
    pub deployment_id: String,
    pub email: String,
    pub password_hash: nazo_identity::ports::PasswordHashInput,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminProvisionReceipt {
    pub operation_id: String,
    pub deployment_id: String,
    pub user_id: Uuid,
    pub email: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminProvisionError {
    InvalidInput,
    EmailConflict,
    OperationConflict,
    Unavailable,
    Storage,
}

impl std::fmt::Display for AdminProvisionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("administrator provisioning failed")
    }
}

impl std::error::Error for AdminProvisionError {}

impl From<diesel::result::Error> for AdminProvisionError {
    fn from(error: diesel::result::Error) -> Self {
        match error {
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            ) => Self::EmailConflict,
            _ => Self::Storage,
        }
    }
}

#[derive(Clone)]
pub struct AdminProvisionRepository {
    pool: DbPool,
}

impl AdminProvisionRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn provision(
        &self,
        request: AdminProvisionRequest,
    ) -> Result<AdminProvisionReceipt, AdminProvisionError> {
        let operation_id = validate_identifier(request.operation_id, MAX_OPERATION_ID_BYTES)?;
        let deployment_id = validate_identifier(request.deployment_id, MAX_DEPLOYMENT_ID_BYTES)?;
        let email = normalize_email_address(&request.email)
            .map_err(|_| AdminProvisionError::InvalidInput)?;
        let tenant = request.tenant;
        let password_hash = request.password_hash.into_persistence_value();
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| AdminProvisionError::Unavailable)?;

        connection
            .transaction::<_, AdminProvisionError, _>(async move |connection| {
                lock_operation(connection, &operation_id).await?;
                if let Some(receipt) = admin_provision_receipts::table
                    .find(&operation_id)
                    .select(AdminProvisionReceiptRow::as_select())
                    .for_update()
                    .first::<AdminProvisionReceiptRow>(connection)
                    .await
                    .optional()?
                {
                    if receipt.deployment_id != deployment_id
                        || receipt.tenant_id != tenant.tenant_id.as_uuid()
                    {
                        return Err(AdminProvisionError::OperationConflict);
                    }
                    let existing_email = users::table
                        .find(receipt.user_id)
                        .filter(users::tenant_id.eq(tenant.tenant_id.as_uuid()))
                        .select(users::email)
                        .for_update()
                        .first::<String>(connection)
                        .await
                        .optional()?
                        .ok_or(AdminProvisionError::Storage)?;
                    if existing_email != email {
                        return Err(AdminProvisionError::OperationConflict);
                    }
                    return Ok(receipt.into_receipt(existing_email));
                }

                if users::table
                    .filter(users::tenant_id.eq(tenant.tenant_id.as_uuid()))
                    .filter(users::email.eq(&email))
                    .select(users::id)
                    .for_update()
                    .first::<Uuid>(connection)
                    .await
                    .optional()?
                    .is_some()
                {
                    return Err(AdminProvisionError::EmailConflict);
                }

                let user_id = Uuid::now_v7();
                let now = Utc::now();
                let username = format!("admin_{}", user_id.simple());
                diesel::insert_into(users::table)
                    .values((
                        users::id.eq(user_id),
                        users::tenant_id.eq(tenant.tenant_id.as_uuid()),
                        users::realm_id.eq(tenant.realm_id.as_uuid()),
                        users::organization_id.eq(tenant.organization_id.as_uuid()),
                        users::username.eq(username),
                        users::email.eq(&email),
                        users::password_hash.eq(password_hash),
                        users::is_active.eq(true),
                        users::email_verified.eq(true),
                        users::role.eq("admin"),
                        users::admin_level.eq(1),
                    ))
                    .execute(connection)
                    .await?;
                diesel::insert_into(admin_provision_receipts::table)
                    .values((
                        admin_provision_receipts::operation_id.eq(&operation_id),
                        admin_provision_receipts::deployment_id.eq(&deployment_id),
                        admin_provision_receipts::tenant_id.eq(tenant.tenant_id.as_uuid()),
                        admin_provision_receipts::user_id.eq(user_id),
                        admin_provision_receipts::created_at.eq(now),
                    ))
                    .execute(connection)
                    .await?;
                diesel::insert_into(identity_security_events::table)
                    .values((
                        identity_security_events::tenant_id.eq(tenant.tenant_id.as_uuid()),
                        identity_security_events::category.eq("admin"),
                        identity_security_events::event_type.eq(ADMIN_PROVISION_EVENT_TYPE),
                        identity_security_events::outcome.eq("success"),
                        identity_security_events::actor_id.eq::<Option<Uuid>>(None),
                        identity_security_events::target_user_id.eq(Some(user_id)),
                        identity_security_events::reason_code.eq(ADMIN_PROVISION_REASON),
                        identity_security_events::occurred_at.eq(now),
                        identity_security_events::request_id.eq(Some(&operation_id)),
                    ))
                    .execute(connection)
                    .await?;

                Ok(AdminProvisionReceipt {
                    operation_id,
                    deployment_id,
                    user_id,
                    email,
                })
            })
            .await
    }
}

impl nazo_persistence::AdminProvisionStore for AdminProvisionRepository {
    fn provision(
        &self,
        request: nazo_persistence::AdminProvisionRequest,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_persistence::AdminProvisionReceipt, nazo_persistence::AdminProvisionError>,
    > {
        Box::pin(async move {
            let receipt = AdminProvisionRepository::provision(
                self,
                AdminProvisionRequest {
                    tenant: request.tenant,
                    operation_id: request.operation_id,
                    deployment_id: request.deployment_id,
                    email: request.email,
                    password_hash: request.password_hash,
                },
            )
            .await
            .map_err(map_admin_provision_error)?;
            Ok(nazo_persistence::AdminProvisionReceipt {
                operation_id: receipt.operation_id,
                deployment_id: receipt.deployment_id,
                user_id: receipt.user_id,
                email: receipt.email,
            })
        })
    }
}

fn map_admin_provision_error(error: AdminProvisionError) -> nazo_persistence::AdminProvisionError {
    match error {
        AdminProvisionError::InvalidInput => nazo_persistence::AdminProvisionError::InvalidInput,
        AdminProvisionError::EmailConflict => nazo_persistence::AdminProvisionError::EmailConflict,
        AdminProvisionError::OperationConflict => {
            nazo_persistence::AdminProvisionError::OperationConflict
        }
        AdminProvisionError::Unavailable => nazo_persistence::AdminProvisionError::Unavailable,
        AdminProvisionError::Storage => nazo_persistence::AdminProvisionError::Storage,
    }
}

#[derive(Clone, Debug, Queryable, Selectable)]
#[diesel(table_name = crate::schema::admin_provision_receipts)]
struct AdminProvisionReceiptRow {
    operation_id: String,
    deployment_id: String,
    tenant_id: Uuid,
    user_id: Uuid,
    created_at: DateTime<Utc>,
}

impl AdminProvisionReceiptRow {
    fn into_receipt(self, email: String) -> AdminProvisionReceipt {
        let Self {
            operation_id,
            deployment_id,
            tenant_id: _,
            user_id,
            created_at,
        } = self;
        let _ = created_at;
        AdminProvisionReceipt {
            operation_id,
            deployment_id,
            user_id,
            email,
        }
    }
}

fn validate_identifier(value: String, max_bytes: usize) -> Result<String, AdminProvisionError> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_+-".contains(character))
    {
        return Err(AdminProvisionError::InvalidInput);
    }
    Ok(value)
}

async fn lock_operation(
    connection: &mut diesel_async::AsyncPgConnection,
    operation_id: &str,
) -> diesel::QueryResult<()> {
    let mut digest = [0_u8; 8];
    digest.copy_from_slice(&sha2::Sha256::digest(operation_id.as_bytes())[..8]);
    let lock_key = i64::from_be_bytes(digest);
    sql_query("SELECT pg_advisory_xact_lock($1)")
        .bind::<BigInt, _>(lock_key)
        .execute(connection)
        .await?;
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/repositories/admin_provision.rs"]
mod tests;
