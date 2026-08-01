//! OIDC 标准 claims 构造。
//! 只从已授权 scope、显式授权的 claims 请求和本地用户事实源生成声明，不为缺失字段写入 null。

use serde_json::{Value, json};

use nazo_auth::OidcClaimRequest;

const PROFILE_CLAIMS: &[&str] = &[
    "preferred_username",
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "updated_at",
];

const EMAIL_CLAIMS: &[&str] = &["email", "email_verified"];
const ADDRESS_CLAIMS: &[&str] = &["address"];
const PHONE_CLAIMS: &[&str] = &["phone_number", "phone_number_verified"];

pub(crate) fn user_claims_are_covered_by_scopes(
    scopes: &[String],
    requested_claims: &[String],
) -> bool {
    requested_claims.iter().all(|claim| {
        let required_scope = if PROFILE_CLAIMS.contains(&claim.as_str()) {
            "profile"
        } else if EMAIL_CLAIMS.contains(&claim.as_str()) {
            "email"
        } else if ADDRESS_CLAIMS.contains(&claim.as_str()) {
            "address"
        } else if PHONE_CLAIMS.contains(&claim.as_str()) {
            "phone"
        } else {
            return false;
        };
        scopes.iter().any(|scope| scope == required_scope)
    })
}

pub(crate) fn oidc_user_claims(
    user: &nazo_identity::SubjectClaims,
    scopes: &[String],
    subject: &str,
    requested_claims: &[String],
    requested_claim_requests: &[OidcClaimRequest],
    _sector_identifier_host: Option<&str>,
) -> Value {
    let mut claims = json!({"sub": subject});
    let has_profile_scope = scopes.iter().any(|scope| scope == "profile");
    let has_email_scope = scopes.iter().any(|scope| scope == "email");
    let has_address_scope = scopes.iter().any(|scope| scope == "address");
    let has_phone_scope = scopes.iter().any(|scope| scope == "phone");

    if claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "preferred_username",
        &json!(user.preferred_username),
    ) {
        claims["preferred_username"] = json!(user.preferred_username);
    }
    let name = user_display_name(user);
    if claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "name",
        &json!(name),
    ) {
        claims["name"] = json!(name);
    }
    if optional_string_claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "given_name",
        user.given_name.as_deref(),
    ) {
        optional_string_claim(&mut claims, "given_name", user.given_name.as_deref());
    }
    if optional_string_claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "family_name",
        user.family_name.as_deref(),
    ) {
        optional_string_claim(&mut claims, "family_name", user.family_name.as_deref());
    }
    if optional_string_claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "middle_name",
        user.middle_name.as_deref(),
    ) {
        optional_string_claim(&mut claims, "middle_name", user.middle_name.as_deref());
    }
    if optional_string_claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "nickname",
        user.nickname.as_deref(),
    ) {
        optional_string_claim(&mut claims, "nickname", user.nickname.as_deref());
    }
    if optional_string_claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "profile",
        user.profile.as_deref(),
    ) {
        optional_string_claim(&mut claims, "profile", user.profile.as_deref());
    }
    if optional_string_claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "picture",
        user.picture.as_deref(),
    ) {
        optional_string_claim(&mut claims, "picture", user.picture.as_deref());
    }
    if optional_string_claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "website",
        user.website.as_deref(),
    ) {
        optional_string_claim(&mut claims, "website", user.website.as_deref());
    }
    if optional_string_claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "gender",
        user.gender.as_deref(),
    ) {
        optional_string_claim(&mut claims, "gender", user.gender.as_deref());
    }
    if optional_string_claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "birthdate",
        user.birthdate.as_deref(),
    ) {
        optional_string_claim(&mut claims, "birthdate", user.birthdate.as_deref());
    }
    if optional_string_claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "zoneinfo",
        user.zoneinfo.as_deref(),
    ) {
        optional_string_claim(&mut claims, "zoneinfo", user.zoneinfo.as_deref());
    }
    if optional_string_claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "locale",
        user.locale.as_deref(),
    ) {
        optional_string_claim(&mut claims, "locale", user.locale.as_deref());
    }
    let updated_at = json!(user.updated_at);
    if claim_allowed(
        has_profile_scope,
        requested_claims,
        requested_claim_requests,
        "updated_at",
        &updated_at,
    ) {
        claims["updated_at"] = json!(user.updated_at);
    }

    if claim_allowed(
        has_email_scope,
        requested_claims,
        requested_claim_requests,
        "email",
        &json!(user.email),
    ) {
        claims["email"] = json!(user.email);
    }
    if claim_allowed(
        has_email_scope,
        requested_claims,
        requested_claim_requests,
        "email_verified",
        &json!(user.email_verified),
    ) {
        claims["email_verified"] = json!(user.email_verified);
    }
    let address = address_claim(user);
    if let Some(address) = address
        && claim_allowed(
            has_address_scope,
            requested_claims,
            requested_claim_requests,
            "address",
            &address,
        )
    {
        claims["address"] = address;
    }
    if optional_string_claim_allowed(
        has_phone_scope,
        requested_claims,
        requested_claim_requests,
        "phone_number",
        user.phone_number.as_deref(),
    ) {
        optional_string_claim(&mut claims, "phone_number", user.phone_number.as_deref());
    }
    if claim_allowed(
        has_phone_scope,
        requested_claims,
        requested_claim_requests,
        "phone_number_verified",
        &json!(user.phone_number_verified),
    ) {
        claims["phone_number_verified"] = json!(user.phone_number_verified);
    }

    claims
}

fn address_claim(user: &nazo_identity::SubjectClaims) -> Option<Value> {
    let source = user.address.as_ref()?;
    let mut address = json!({});
    optional_string_claim(&mut address, "formatted", source.formatted.as_deref());
    optional_string_claim(
        &mut address,
        "street_address",
        source.street_address.as_deref(),
    );
    optional_string_claim(&mut address, "locality", source.locality.as_deref());
    optional_string_claim(&mut address, "region", source.region.as_deref());
    optional_string_claim(&mut address, "postal_code", source.postal_code.as_deref());
    optional_string_claim(&mut address, "country", source.country.as_deref());
    address
        .as_object()
        .is_some_and(|object| !object.is_empty())
        .then_some(address)
}

fn optional_string_claim(claims: &mut Value, name: &str, value: Option<&str>) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        claims[name] = json!(value);
    }
}

fn requested_claim(requested_claims: &[String], name: &str) -> bool {
    requested_claims.iter().any(|claim| claim == name)
}

fn claim_requested(
    requested_claims: &[String],
    requested_claim_requests: &[OidcClaimRequest],
    name: &str,
) -> bool {
    requested_claim(requested_claims, name)
        || requested_claim_requests
            .iter()
            .any(|request| request.name == name)
}

fn claim_allowed(
    scope_allowed: bool,
    requested_claims: &[String],
    requested_claim_requests: &[OidcClaimRequest],
    name: &str,
    actual: &Value,
) -> bool {
    if let Some(request) = requested_claim_requests
        .iter()
        .find(|request| request.name == name)
    {
        return claim_value_matches_request(request, actual);
    }
    if requested_claim(requested_claims, name) {
        return true;
    }
    scope_allowed && !claim_requested(requested_claims, requested_claim_requests, name)
}

fn optional_string_claim_allowed(
    scope_allowed: bool,
    requested_claims: &[String],
    requested_claim_requests: &[OidcClaimRequest],
    name: &str,
    actual: Option<&str>,
) -> bool {
    let Some(actual) = actual.map(str::trim).filter(|value| !value.is_empty()) else {
        return false;
    };
    claim_allowed(
        scope_allowed,
        requested_claims,
        requested_claim_requests,
        name,
        &json!(actual),
    )
}

fn claim_value_matches_request(request: &OidcClaimRequest, actual: &Value) -> bool {
    match (&request.value, request.values.as_slice()) {
        (Some(expected), _) => expected == actual,
        (None, []) => true,
        (None, values) => values.iter().any(|expected| expected == actual),
    }
}

fn user_display_name(user: &nazo_identity::SubjectClaims) -> &str {
    user.name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&user.preferred_username)
}

pub(crate) fn oidc_id_token_user_claims(
    user: &nazo_identity::SubjectClaims,
    scopes: &[String],
    subject: &str,
    requested_claims: &[String],
    requested_claim_requests: &[OidcClaimRequest],
    sector_identifier_host: Option<&str>,
) -> Value {
    let mut claims = oidc_user_claims(
        user,
        scopes,
        subject,
        requested_claims,
        requested_claim_requests,
        sector_identifier_host,
    );
    if let Some(object) = claims.as_object_mut() {
        if !claim_requested(requested_claims, requested_claim_requests, "email") {
            object.remove("email");
        }
        if !claim_requested(requested_claims, requested_claim_requests, "email_verified") {
            object.remove("email_verified");
        }
        if !claim_requested(requested_claims, requested_claim_requests, "address") {
            object.remove("address");
        }
        if !claim_requested(requested_claims, requested_claim_requests, "phone_number") {
            object.remove("phone_number");
        }
        if !claim_requested(
            requested_claims,
            requested_claim_requests,
            "phone_number_verified",
        ) {
            object.remove("phone_number_verified");
        }
    }
    claims
}

#[cfg(test)]
#[path = "../../tests/unit/domain/oidc_claims.rs"]
mod tests;
