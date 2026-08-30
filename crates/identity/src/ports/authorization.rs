use chrono::{DateTime, Utc};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

use crate::{AccessRequest, NewAccessRequest, TenantId, UserId};

use super::common::RepositoryFuture;

pub trait GrantSummaryRepositoryPort: Send + Sync {
    fn authorized_client_count(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
    ) -> RepositoryFuture<'_, i64>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct AuthorizedApplication {
    pub client_id: String,
    pub client_name: String,
    pub last_scopes: Value,
    pub last_authorized_at: DateTime<Utc>,
    pub authorization_count: i32,
}

pub trait AuthorizedApplicationRepositoryPort: Send + Sync {
    fn applications_for_user(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
    ) -> RepositoryFuture<'_, Vec<AuthorizedApplication>>;
}

pub trait AccessRequestRepositoryPort: Send + Sync {
    fn list_for_user(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Vec<AccessRequest>>;

    fn create(&self, request: NewAccessRequest) -> RepositoryFuture<'_, AccessRequest>;

    fn approved_delivery_matches<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        request_id: Uuid,
        approved_client_id: Uuid,
        client_id: &'a str,
    ) -> RepositoryFuture<'a, bool>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeliveryRecord {
    pub value: Value,
    pub opaque_version: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DeliveryConsume {
    Consumed(Value),
    MissingOrChanged,
}

pub trait DeliveryStorePort: Send + Sync {
    fn store<'a>(
        &'a self,
        user_id: UserId,
        token: &'a str,
        payload: &'a Value,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()>;

    fn load<'a>(
        &'a self,
        user_id: UserId,
        token: &'a str,
    ) -> RepositoryFuture<'a, Option<DeliveryRecord>>;

    fn load_many<'a>(
        &'a self,
        lookups: &'a [(UserId, &'a str)],
    ) -> RepositoryFuture<'a, Vec<Option<DeliveryRecord>>>;

    fn delete<'a>(&'a self, user_id: UserId, token: &'a str) -> RepositoryFuture<'a, ()>;

    fn consume<'a>(
        &'a self,
        user_id: UserId,
        token: &'a str,
        expected: &'a DeliveryRecord,
    ) -> RepositoryFuture<'a, DeliveryConsume>;
}

impl<T> DeliveryStorePort for Arc<T>
where
    T: DeliveryStorePort + ?Sized,
{
    fn store<'a>(
        &'a self,
        user_id: UserId,
        token: &'a str,
        payload: &'a Value,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        self.as_ref().store(user_id, token, payload, ttl_seconds)
    }

    fn load<'a>(
        &'a self,
        user_id: UserId,
        token: &'a str,
    ) -> RepositoryFuture<'a, Option<DeliveryRecord>> {
        self.as_ref().load(user_id, token)
    }

    fn load_many<'a>(
        &'a self,
        lookups: &'a [(UserId, &'a str)],
    ) -> RepositoryFuture<'a, Vec<Option<DeliveryRecord>>> {
        self.as_ref().load_many(lookups)
    }

    fn delete<'a>(&'a self, user_id: UserId, token: &'a str) -> RepositoryFuture<'a, ()> {
        self.as_ref().delete(user_id, token)
    }

    fn consume<'a>(
        &'a self,
        user_id: UserId,
        token: &'a str,
        expected: &'a DeliveryRecord,
    ) -> RepositoryFuture<'a, DeliveryConsume> {
        self.as_ref().consume(user_id, token, expected)
    }
}
