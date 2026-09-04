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
    fn encode(format: image::ImageFormat) -> Vec<u8> {
        let mut encoded = std::io::Cursor::new(Vec::new());
        image::DynamicImage::new_rgba8(1, 1)
            .write_to(&mut encoded, format)
            .expect("fixture image should encode");
        encoded.into_inner()
    }

    let png = encode(image::ImageFormat::Png);
    let jpeg = encode(image::ImageFormat::Jpeg);
    let webp = encode(image::ImageFormat::WebP);
    assert_eq!(
        AvatarContentType::detect(&png),
        Some(AvatarContentType::Png)
    );
    assert_eq!(
        AvatarContentType::detect(&jpeg),
        Some(AvatarContentType::Jpeg)
    );
    assert_eq!(
        AvatarContentType::detect(&webp),
        Some(AvatarContentType::Webp)
    );
    assert_eq!(AvatarContentType::detect(b"\x89PNG\r\n\x1a\nnot-an-image"), None);
    assert_eq!(AvatarContentType::detect(b"not-an-image"), None);
}
