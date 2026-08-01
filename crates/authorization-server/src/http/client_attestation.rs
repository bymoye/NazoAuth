use actix_web::http::header::HeaderMap;

const CLIENT_ATTESTATION: &str = "OAuth-Client-Attestation";
const CLIENT_ATTESTATION_POP: &str = "OAuth-Client-Attestation-PoP";

pub(crate) fn client_attestation_headers(headers: &HeaderMap) -> Result<Option<(&str, &str)>, ()> {
    let attestation = exactly_one_header(headers, CLIENT_ATTESTATION)?;
    let proof = exactly_one_header(headers, CLIENT_ATTESTATION_POP)?;
    match (attestation, proof) {
        (None, None) => Ok(None),
        (Some(attestation), Some(proof)) => Ok(Some((attestation, proof))),
        _ => Err(()),
    }
}

fn exactly_one_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<Option<&'a str>, ()> {
    let mut values = headers.get_all(name);
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    value
        .to_str()
        .ok()
        .filter(|value| !value.is_empty())
        .map(Some)
        .ok_or(())
}

#[cfg(test)]
#[path = "../../tests/unit/http/client_attestation.rs"]
mod tests;
