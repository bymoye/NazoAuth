use anyhow::Context as _;

pub(super) const CIBA_PING_TLS_MIN: reqwest::tls::Version = reqwest::tls::Version::TLS_1_2;
pub(super) const CIBA_PING_TLS_MAX: reqwest::tls::Version = reqwest::tls::Version::TLS_1_3;

pub(super) fn apply_ciba_ping_tls_policy(
    mut builder: reqwest::ClientBuilder,
) -> anyhow::Result<reqwest::ClientBuilder> {
    builder = builder
        .use_rustls_tls()
        .tls_version_min(CIBA_PING_TLS_MIN)
        .tls_version_max(CIBA_PING_TLS_MAX);
    if let Some(path) = std::env::var_os("CIBA_PING_TLS_TRUST_BUNDLE") {
        let bundle = std::fs::read(&path).with_context(|| {
            format!(
                "failed to read CIBA ping TLS trust bundle {}",
                std::path::Path::new(&path).display()
            )
        })?;
        let certificates = reqwest::Certificate::from_pem_bundle(&bundle)
            .context("failed to parse CIBA ping TLS trust bundle")?;
        if certificates.is_empty() {
            anyhow::bail!("CIBA ping TLS trust bundle contains no certificates");
        }
        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
    }
    Ok(builder)
}
