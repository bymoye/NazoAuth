use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{TenantId, UserId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i16)]
pub enum AccessRequestStatus {
    Pending = 0,
    Approved = 1,
    Rejected = 2,
}

impl AccessRequestStatus {
    #[must_use]
    pub const fn code(self) -> i16 {
        self as i16
    }

    #[must_use]
    pub const fn from_code(code: i16) -> Option<Self> {
        match code {
            0 => Some(Self::Pending),
            1 => Some(Self::Approved),
            2 => Some(Self::Rejected),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessRequest {
    pub id: Uuid,
    pub tenant_id: TenantId,
    pub user_id: UserId,
    pub requester_email: Option<String>,
    pub site_name: String,
    pub site_url: String,
    pub request_description: String,
    pub status: AccessRequestStatus,
    pub admin_note: Option<String>,
    pub approved_client_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewAccessRequest {
    pub tenant_id: TenantId,
    pub user_id: UserId,
    pub site_name: String,
    pub site_url: String,
    pub request_description: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessRequestPage {
    pub total: i64,
    pub items: Vec<AccessRequest>,
}
