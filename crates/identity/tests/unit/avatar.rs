use super::*;

#[test]
fn avatar_reference_rejects_extra_query_or_path_components() {
    assert_eq!(avatar_url_version("/auth/me/avatar?v=v1"), Ok("v1"));
    assert!(avatar_url_version("/auth/me/avatar?v=v1&x=1").is_err());
    assert!(avatar_url_version("/auth/me/avatar?v=../x").is_err());
    assert!(avatar_url_version("https://example.com/avatar?v=v1").is_err());
}

#[test]
fn content_detection_uses_file_signatures() {
    assert_eq!(
        AvatarContentType::detect(b"\x89PNG\r\n\x1a\nrest"),
        Some(AvatarContentType::Png)
    );
    assert_eq!(
        AvatarContentType::detect(b"\xff\xd8\xffrest"),
        Some(AvatarContentType::Jpeg)
    );
    assert_eq!(
        AvatarContentType::detect(b"RIFFxxxxWEBPrest"),
        Some(AvatarContentType::Webp)
    );
    assert_eq!(AvatarContentType::detect(b"not-an-image"), None);
}
