use super::*;

#[test]
fn embedded_descriptor_is_closed_and_valid() {
    let descriptor: FrontendDescriptor = serde_json::from_str(DEFAULT_FRONTEND).unwrap();
    descriptor.validate().unwrap();
    assert_eq!(
        descriptor.url().unwrap().as_str(),
        "https://github.com/nazozero/NazoAuthWeb/releases/download/v0.2.0/nazoauth-web.tar.gz"
    );
    let mut value: serde_json::Value = serde_json::from_str(DEFAULT_FRONTEND).unwrap();
    value["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<FrontendDescriptor>(value).is_err());
}

#[test]
fn archive_paths_reject_parent_absolute_and_platform_prefixes() {
    assert!(safe_relative(Path::new("./assets/app.js")));
    assert!(!safe_relative(Path::new("../index.html")));
    assert!(!safe_relative(Path::new("/index.html")));
    assert!(!safe_relative(Path::new("C:\\index.html")));
}

#[test]
fn frontend_downloads_stay_on_explicit_github_https_origins() {
    for accepted in [
        "https://github.com/nazozero/NazoAuthWeb/releases/download/v0.2.0/nazoauth-web.tar.gz",
        "https://objects.githubusercontent.com/object",
        "https://release-assets.githubusercontent.com/object?token=opaque",
    ] {
        assert!(allowed_download_url(&Url::parse(accepted).unwrap()));
    }
    for rejected in [
        "http://github.com/object",
        "https://user@github.com/object",
        "https://github.com:444/object",
        "https://github.com.evil.example/object",
        "https://127.0.0.1/object",
        "https://release-assets.githubusercontent.com/object#fragment",
    ] {
        assert!(!allowed_download_url(&Url::parse(rejected).unwrap()));
    }
}

#[test]
fn corrupt_or_incomplete_cache_is_never_reused() {
    let descriptor: FrontendDescriptor = serde_json::from_str(DEFAULT_FRONTEND).unwrap();
    let root = std::env::temp_dir().join(format!("nazoauth-ui-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&root).unwrap();
    assert!(!cached_release_valid(&root, &descriptor).unwrap());
    fs::write(root.join("index.html"), b"fixture").unwrap();
    fs::write(root.join(".nazoauth-ui.json"), b"{}").unwrap();
    assert!(cached_release_valid(&root, &descriptor).is_err());
    fs::write(
        root.join(".nazoauth-ui.json"),
        serde_json::to_vec(&descriptor).unwrap(),
    )
    .unwrap();
    assert!(cached_release_valid(&root, &descriptor).unwrap());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn bounded_regular_archive_extracts_without_external_ui_source() {
    use flate2::{Compression, write::GzEncoder};
    use tar::{Builder, Header};

    let root = std::env::temp_dir().join(format!("nazoauth-ui-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&root).unwrap();
    let archive_path = root.join("ui.tar.gz");
    let output = root.join("output");
    fs::create_dir(&output).unwrap();
    let archive = File::create(&archive_path).unwrap();
    let mut builder = Builder::new(GzEncoder::new(archive, Compression::default()));
    let mut header = Header::new_gnu();
    header.set_size(7);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "index.html", &b"fixture"[..])
        .unwrap();
    builder.into_inner().unwrap().finish().unwrap();

    extract(&archive_path, &output).unwrap();
    assert_eq!(fs::read(output.join("index.html")).unwrap(), b"fixture");
    fs::remove_dir_all(root).unwrap();
}
