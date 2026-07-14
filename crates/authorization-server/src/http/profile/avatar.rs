//! Current-user avatar HTTP transport.
use crate::http::views::auth_me_json_with_count;
use crate::http::{sessions::SessionProfileHandles, views::is_cross_site_fetch};
use actix_multipart::Multipart;
use actix_web::http::header::HeaderValue;
use actix_web::{
    HttpRequest, HttpResponse,
    http::{StatusCode, header},
    web::Data,
};
use futures_util::StreamExt as _;
use nazo_http_actix::{bytes_response, csrf_error, json_response, oauth_error};

pub(crate) async fn upload_avatar(
    sessions: Data<SessionProfileHandles>,
    avatars: Data<crate::bootstrap::AvatarProfileService>,
    req: HttpRequest,
    mut multipart: Multipart,
) -> HttpResponse {
    if !sessions.has_valid_csrf_token(&req, None) {
        return csrf_error();
    }
    let user = match sessions.current_user_or_login_required(&req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    while let Some(field) = multipart.next().await {
        let mut field = match field {
            Ok(field) => field,
            Err(_) => return invalid_avatar_read_response(),
        };
        if field.name() != Some("avatar") {
            continue;
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = field.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(_) => return invalid_avatar_read_response(),
            };
            if chunk.len() > avatars.max_bytes().saturating_sub(bytes.len()) {
                return oauth_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "invalid_request",
                    "头像文件过大.",
                );
            }
            bytes.extend_from_slice(&chunk);
        }
        return match avatars.upload(&user, bytes).await {
            Ok(overview) => json_response(auth_me_json_with_count(
                &overview.account,
                overview.authorized_application_count,
            )),
            Err(nazo_identity::UploadAvatarError::TooLarge) => oauth_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request",
                "头像文件过大.",
            ),
            Err(nazo_identity::UploadAvatarError::UnsupportedContent) => oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "头像仅支持 PNG、JPEG、WEBP 格式.",
            ),
            Err(nazo_identity::UploadAvatarError::Storage(
                nazo_identity::ports::AvatarStorageError::PreparationFailed(error),
            )) => {
                tracing::warn!(%error, "failed to prepare avatar storage");
                oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "头像保存失败.",
                )
            }
            Err(nazo_identity::UploadAvatarError::Overview(error)) => {
                tracing::warn!(%error, "failed to build auth me response after avatar upload");
                oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "当前用户资料查询失败.",
                )
            }
            Err(error) => {
                tracing::warn!(?error, "failed to save avatar");
                oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "头像保存失败.",
                )
            }
        };
    }
    oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "缺少 avatar 文件.",
    )
}

fn invalid_avatar_read_response() -> HttpResponse {
    oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "头像文件读取失败.",
    )
}

pub(crate) async fn get_avatar(
    sessions: Data<SessionProfileHandles>,
    avatars: Data<crate::bootstrap::AvatarProfileService>,
    req: HttpRequest,
) -> HttpResponse {
    let user = match sessions.current_user_or_login_required(&req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if is_cross_site_fetch(req.headers()) {
        return oauth_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "跨站请求头像资源被拒绝.",
        );
    }
    let avatar = avatars.read(&user).await;
    let avatar = match avatar {
        Err(nazo_identity::ReadAvatarError::Storage(
            nazo_identity::ports::AvatarStorageError::Conflict
            | nazo_identity::ports::AvatarStorageError::InvalidState
            | nazo_identity::ports::AvatarStorageError::Missing,
        )) => {
            // A request may have loaded the account immediately before an upload/delete
            // commits. The storage mutation is serialized, so refresh the projection once
            // after it completes rather than exposing a transient mixed version.
            let refreshed = match sessions.current_user_or_login_required(&req).await {
                Ok(user) => user,
                Err(response) => return response,
            };
            avatars.read(&refreshed).await
        }
        result => result,
    };
    match avatar {
        Ok(avatar) => {
            let mut response = bytes_response(avatar.bytes);
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(avatar.content_type.as_str()),
            );
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, no-store, no-cache, must-revalidate"),
            );
            response
                .headers_mut()
                .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
            response.headers_mut().insert(
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            );
            response.headers_mut().insert(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static("default-src 'none'"),
            );
            response
        }
        Err(nazo_identity::ReadAvatarError::NotUploaded) => oauth_error(
            StatusCode::NOT_FOUND,
            "invalid_request",
            "当前用户尚未上传头像.",
        ),
        Err(error) => {
            tracing::warn!(?error, "failed to read avatar");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "头像读取失败.",
            )
        }
    }
}

pub(crate) async fn delete_avatar(
    sessions: Data<SessionProfileHandles>,
    avatars: Data<crate::bootstrap::AvatarProfileService>,
    req: HttpRequest,
) -> HttpResponse {
    if !sessions.has_valid_csrf_token(&req, None) {
        return csrf_error();
    }
    let user = match sessions.current_user_or_login_required(&req).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    match avatars.delete(&user).await {
        Ok(overview) => json_response(auth_me_json_with_count(
            &overview.account,
            overview.authorized_application_count,
        )),
        Err(nazo_identity::DeleteAvatarError::Overview(error)) => {
            tracing::warn!(%error, "failed to build auth me response after avatar delete");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "当前用户资料查询失败.",
            )
        }
        Err(error) => {
            tracing::warn!(?error, "failed to delete avatar");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "头像删除失败.",
            )
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/profile/tests/avatar.rs"]
mod tests;
