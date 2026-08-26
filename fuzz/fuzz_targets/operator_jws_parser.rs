#![no_main]

use ed25519_dalek::SigningKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let key = SigningKey::from_bytes(&[0x42; 32]);
    let verifying_key = key.verifying_key();
    let _ = nazo_operator_protocol::protected_header(&input);
    let kid = nazo_operator_protocol::controller_key_id(&verifying_key);
    let _ = nazo_operator_protocol::verify_control_operation_signature(
        &input,
        &kid,
        &verifying_key,
    );
});
