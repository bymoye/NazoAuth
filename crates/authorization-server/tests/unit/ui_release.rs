use super::*;

#[test]
fn embedded_descriptor_is_closed_and_valid() {
    let descriptor: FrontendDescriptor = serde_json::from_str(DEFAULT_FRONTEND).unwrap();
    descriptor.validate().unwrap();
    assert_eq!(
        descriptor.url().unwrap().as_str(),
        "https://github.com/nazozero/NazoAuthWeb/releases/download/v0.2.2/nazoauth-web.tar.gz"
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
        "https://github.com/nazozero/NazoAuthWeb/releases/download/v0.2.2/nazoauth-web.tar.gz",
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

#[test]
fn frontend_descriptor_policy_rejects_each_untrusted_binding() {
    let descriptor: FrontendDescriptor = serde_json::from_str(DEFAULT_FRONTEND).unwrap();
    let mut invalid = Vec::new();
    for mutate in [
        |value: &mut FrontendDescriptor| value.schema = 2,
        |value: &mut FrontendDescriptor| value.repository = "other/repository".to_owned(),
        |value: &mut FrontendDescriptor| value.version = "latest".to_owned(),
        |value: &mut FrontendDescriptor| value.commit = "A".repeat(40),
        |value: &mut FrontendDescriptor| {
            value.release_identity = "https://example.invalid".to_owned()
        },
        |value: &mut FrontendDescriptor| value.artifact.repository = "other/repository".to_owned(),
        |value: &mut FrontendDescriptor| value.artifact.name = "frontend.zip".to_owned(),
        |value: &mut FrontendDescriptor| value.artifact.sha256 = "A".repeat(64),
        |value: &mut FrontendDescriptor| value.artifact.size = 0,
        |value: &mut FrontendDescriptor| value.artifact.size = MAX_ARCHIVE_BYTES + 1,
    ] {
        let mut value = descriptor.clone();
        mutate(&mut value);
        invalid.push(value);
    }
    for value in invalid {
        assert!(value.validate().is_err());
    }
    assert!(!semantic_tag("0.1.0"));
    assert!(!semantic_tag("v01.0.0"));
    assert!(!lower_hex("ABC", 3));
    assert_eq!(hex(&[0, 15, 255]), "000fff");
}

#[tokio::test]
async fn explicit_static_and_valid_cached_ui_paths_resolve_without_download() {
    let root = std::env::temp_dir().join(format!("nazoauth-ui-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&root).unwrap();
    let static_directory = root.join("static");
    fs::create_dir(&static_directory).unwrap();
    assert!(validate_static_directory(&static_directory).is_err());
    fs::write(static_directory.join("index.html"), b"fixture").unwrap();
    let config = ConfigSource::from_owned_pairs_for_test([(
        "UI_STATIC_DIR".to_owned(),
        static_directory.display().to_string(),
    )]);
    assert_eq!(
        resolve(&config).await.unwrap().unwrap(),
        fs::canonicalize(&static_directory).unwrap()
    );

    let descriptor: FrontendDescriptor = serde_json::from_str(DEFAULT_FRONTEND).unwrap();
    let cache = root.join("cache");
    let target = cache.join(&descriptor.artifact.sha256);
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("index.html"), b"fixture").unwrap();
    fs::write(
        target.join(".nazoauth-ui.json"),
        serde_json::to_vec(&descriptor).unwrap(),
    )
    .unwrap();
    assert_eq!(
        ensure_cached(&cache, &descriptor).await.unwrap(),
        fs::canonicalize(&target).unwrap()
    );

    fs::remove_file(target.join(".nazoauth-ui.json")).unwrap();
    assert!(ensure_cached(&cache, &descriptor).await.is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn private_ui_tree_and_archive_fail_closed_without_index() {
    use flate2::{Compression, write::GzEncoder};
    use tar::{Builder, Header};

    let root = std::env::temp_dir().join(format!("nazoauth-ui-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&root).unwrap();
    let tree = root.join("tree");
    let private = tree.join("nested/asset.js");
    fs::create_dir_all(private.parent().unwrap()).unwrap();
    write_private(&private, b"asset").unwrap();
    make_tree_read_only(&tree).unwrap();
    assert_eq!(fs::read(&private).unwrap(), b"asset");

    let archive_path = root.join("missing-index.tar.gz");
    let output = root.join("output");
    fs::create_dir(&output).unwrap();
    let archive = File::create(&archive_path).unwrap();
    let mut builder = Builder::new(GzEncoder::new(archive, Compression::default()));
    let mut header = Header::new_gnu();
    header.set_size(5);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "asset.js", &b"asset"[..])
        .unwrap();
    builder.into_inner().unwrap().finish().unwrap();
    assert!(extract(&archive_path, &output).is_err());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        for (path, mode) in [
            (private.as_path(), 0o600),
            (private.parent().unwrap(), 0o700),
            (tree.as_path(), 0o700),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
    }
    #[cfg(windows)]
    #[allow(clippy::permissions_set_readonly_false)]
    {
        for path in [private.as_path(), private.parent().unwrap(), tree.as_path()] {
            let mut permissions = fs::metadata(path).unwrap().permissions();
            permissions.set_readonly(false);
            fs::set_permissions(path, permissions).unwrap();
        }
    }
    fs::remove_dir_all(root).unwrap();
}
