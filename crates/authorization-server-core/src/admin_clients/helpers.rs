use super::errors::AdminClientError;

pub(super) fn trim_optional_string(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

pub(super) fn trim_string_vec(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect()
}

pub(super) fn all_same_host(uris: &[String]) -> Option<String> {
    let mut hosts = uris
        .iter()
        .filter_map(|uri| url::Url::parse(uri).ok()?.host_str().map(ToOwned::to_owned));
    let first = hosts.next()?;
    hosts.all(|host| host == first).then_some(first)
}

pub(super) fn sector_identifier_host_for_redirects(
    uri: &str,
    redirect_uris: &[String],
    sector_uris: &[String],
) -> Result<String, AdminClientError> {
    for redirect_uri in redirect_uris {
        if !sector_uris.contains(redirect_uri) {
            return Err(AdminClientError::InvalidRequest(format!(
                "redirect_uri {redirect_uri} 不在 sector_identifier_uri 返回列表中"
            )));
        }
    }
    url::Url::parse(uri)
        .ok()
        .and_then(|url| url.host_str().map(ToOwned::to_owned))
        .ok_or_else(|| {
            AdminClientError::InvalidRequest(
                "sector_identifier_uri host 解析失败: InvalidUri".to_owned(),
            )
        })
}
