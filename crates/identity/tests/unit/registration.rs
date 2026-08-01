use super::random_numeric_code;

#[test]
fn verification_codes_are_fixed_width_decimal_values() {
    for _ in 0..64 {
        let code = random_numeric_code();
        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|byte| byte.is_ascii_digit()));
    }
}
