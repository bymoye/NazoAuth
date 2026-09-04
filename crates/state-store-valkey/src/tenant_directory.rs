use std::collections::HashSet;

use fred::prelude::{KeysInterface, LuaInterface};
use nazo_identity::{
    OrganizationId, RealmId, TenantContext, TenantDirectoryBinding, TenantDirectorySnapshot,
    TenantId, canonical_tenant_host,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Error, ValkeyClient};

const CACHE_SCHEMA_VERSION: u8 = 2;
const CACHE_INTEGRITY_MARKER: &str = "nazo-tenant-directory-cache-v2";
const SNAPSHOT_KEY: &str = "tenant-directory:snapshot";

const PUBLISH_AUTHORITATIVE_SCRIPT: &str = r#"
local function valid_revision(value)
  if not string.match(value, '^%d+$') then
    return false
  end
  if string.len(value) > 1 and string.sub(value, 1, 1) == '0' then
    return false
  end
  if string.len(value) > 20 then
    return false
  end
  if string.len(value) == 20 and value > '18446744073709551615' then
    return false
  end
  return true
end

local function valid_snapshot(current)
  if type(current) ~= 'table' or current.schema_version ~= 2 or
     current.integrity ~= 'nazo-tenant-directory-cache-v2' or
     type(current.revision) ~= 'string' or not valid_revision(current.revision) or
     type(current.tenants) ~= 'table' then
    return false
  end
  for index, tenant in pairs(current.tenants) do
    if type(index) ~= 'number' or index < 1 or index % 1 ~= 0 or
       type(tenant) ~= 'table' or
       type(tenant.tenant_id) ~= 'string' or tenant.tenant_id == '' or
       type(tenant.realm_id) ~= 'string' or tenant.realm_id == '' or
       type(tenant.organization_id) ~= 'string' or tenant.organization_id == '' or
       type(tenant.runtime_revision) ~= 'string' or tenant.runtime_revision == '0' or
       not valid_revision(tenant.runtime_revision) or
       type(tenant.issuer) ~= 'string' or tenant.issuer == '' or
       type(tenant.external_host) ~= 'string' or tenant.external_host == '' then
      return false
    end
  end
  return true
end

local current_json = redis.call('GET', KEYS[1])
if current_json then
  local decoded_ok, current = pcall(cjson.decode, current_json)
  if decoded_ok and valid_snapshot(current) then
    if string.len(current.revision) > string.len(ARGV[1]) or
       (string.len(current.revision) == string.len(ARGV[1]) and current.revision > ARGV[1]) then
      return 'not_newer'
    end
    if current.revision == ARGV[1] and current_json == ARGV[2] then
      return 'not_newer'
    end
  end
end
redis.call('SET', KEYS[1], ARGV[2])
return 'stored'
"#;

/// Deployment-wide cache for the public tenant routing directory.
#[derive(Clone)]
pub struct TenantDirectoryCache {
    client: ValkeyClient,
}

impl TenantDirectoryCache {
    #[must_use]
    pub fn new(client: &ValkeyClient) -> Self {
        Self {
            client: client.clone(),
        }
    }

    pub async fn load(&self) -> Result<Option<TenantDirectorySnapshot>, Error> {
        let snapshot: Option<String> = self
            .client
            .client
            .get(self.client.deployment_key(SNAPSHOT_KEY))
            .await
            .map_err(Error::from_fred)?;
        snapshot
            .map(|snapshot| decode_snapshot(&snapshot))
            .transpose()
    }

    /// Publishes a database-authoritative snapshot without allowing a lower
    /// revision to replace a valid newer cache entry.
    pub async fn publish_authoritative(
        &self,
        snapshot: &TenantDirectorySnapshot,
    ) -> Result<bool, Error> {
        let encoded = encode_snapshot(snapshot)?;
        let reply: String = self
            .client
            .client
            .eval(
                PUBLISH_AUTHORITATIVE_SCRIPT,
                vec![self.client.deployment_key(SNAPSHOT_KEY)],
                vec![snapshot.revision.to_string(), encoded],
            )
            .await
            .map_err(Error::from_fred)?;
        match reply.as_str() {
            "stored" => Ok(true),
            "not_newer" => Ok(false),
            other => Err(Error::unexpected(format!(
                "unexpected tenant directory CAS reply {other:?}"
            ))),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CachedDirectorySnapshot {
    schema_version: u8,
    integrity: String,
    revision: String,
    tenants: Vec<CachedDirectoryBinding>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CachedDirectoryBinding {
    tenant_id: Uuid,
    realm_id: Uuid,
    organization_id: Uuid,
    runtime_revision: String,
    issuer: String,
    external_host: String,
}

fn encode_snapshot(snapshot: &TenantDirectorySnapshot) -> Result<String, Error> {
    validate_bindings(&snapshot.tenants, Error::unexpected)?;
    let wire = CachedDirectorySnapshot {
        schema_version: CACHE_SCHEMA_VERSION,
        integrity: CACHE_INTEGRITY_MARKER.to_owned(),
        revision: snapshot.revision.to_string(),
        tenants: snapshot
            .tenants
            .iter()
            .map(|binding| CachedDirectoryBinding {
                tenant_id: binding.tenant.tenant_id.as_uuid(),
                realm_id: binding.tenant.realm_id.as_uuid(),
                organization_id: binding.tenant.organization_id.as_uuid(),
                runtime_revision: binding.runtime_revision.to_string(),
                issuer: binding.issuer.clone(),
                external_host: binding.external_host.clone(),
            })
            .collect(),
    };
    serde_json::to_string(&wire)
        .map_err(|error| Error::unexpected(format!("failed to encode tenant directory: {error}")))
}

fn decode_snapshot(encoded: &str) -> Result<TenantDirectorySnapshot, Error> {
    let wire: CachedDirectorySnapshot = serde_json::from_str(encoded).map_err(|error| {
        Error::corrupt_data(format!("cached tenant directory JSON is invalid: {error}"))
    })?;
    if wire.schema_version != CACHE_SCHEMA_VERSION {
        return Err(Error::corrupt_data(
            "cached tenant directory schema version is unsupported",
        ));
    }
    if wire.integrity != CACHE_INTEGRITY_MARKER {
        return Err(Error::corrupt_data(
            "cached tenant directory integrity marker is invalid",
        ));
    }
    let revision = wire.revision.parse::<u64>().map_err(|_| {
        Error::corrupt_data("cached tenant directory revision is not a canonical u64")
    })?;
    if wire.revision != revision.to_string() {
        return Err(Error::corrupt_data(
            "cached tenant directory revision is not canonical",
        ));
    }
    let tenants = wire
        .tenants
        .into_iter()
        .map(|binding| {
            let runtime_revision = binding.runtime_revision.parse::<u64>().map_err(|_| {
                Error::corrupt_data("cached tenant runtime revision is not a canonical u64")
            })?;
            if binding.runtime_revision != runtime_revision.to_string() {
                return Err(Error::corrupt_data(
                    "cached tenant runtime revision is not canonical",
                ));
            }
            Ok(TenantDirectoryBinding {
                tenant: TenantContext {
                    tenant_id: TenantId::new(binding.tenant_id).map_err(|_| {
                        Error::corrupt_data("cached tenant directory contains a nil tenant id")
                    })?,
                    realm_id: RealmId::new(binding.realm_id).map_err(|_| {
                        Error::corrupt_data("cached tenant directory contains a nil realm id")
                    })?,
                    organization_id: OrganizationId::new(binding.organization_id).map_err(
                        |_| {
                            Error::corrupt_data(
                                "cached tenant directory contains a nil organization id",
                            )
                        },
                    )?,
                },
                runtime_revision,
                issuer: binding.issuer,
                external_host: binding.external_host,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    validate_bindings(&tenants, Error::corrupt_data)?;
    Ok(TenantDirectorySnapshot { revision, tenants })
}

fn validate_bindings(
    tenants: &[TenantDirectoryBinding],
    invalid: fn(String) -> Error,
) -> Result<(), Error> {
    let mut tenant_ids = HashSet::with_capacity(tenants.len());
    let mut issuers = HashSet::with_capacity(tenants.len());
    let mut hosts = HashSet::with_capacity(tenants.len());
    for binding in tenants {
        if binding.runtime_revision == 0 {
            return Err(invalid(
                "tenant runtime revision must be positive".to_owned(),
            ));
        }
        nazo_auth::validate_issuer_url(&binding.issuer)
            .map_err(|error| invalid(format!("tenant directory issuer is invalid: {error}")))?;
        let host = canonical_tenant_host(&binding.external_host).map_err(|error| {
            invalid(format!(
                "tenant directory external host is invalid: {error}"
            ))
        })?;
        if host != binding.external_host {
            return Err(invalid(
                "tenant directory external host is not canonical".to_owned(),
            ));
        }
        if !tenant_ids.insert(binding.tenant.tenant_id) {
            return Err(invalid(
                "tenant directory contains a duplicate tenant id".to_owned(),
            ));
        }
        if !issuers.insert(binding.issuer.as_str()) {
            return Err(invalid(
                "tenant directory contains a duplicate issuer".to_owned(),
            ));
        }
        if !hosts.insert(binding.external_host.as_str()) {
            return Err(invalid(
                "tenant directory contains a duplicate external host".to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/tenant_directory.rs"]
mod tests;
