#![no_main]

use ed25519_dalek::SigningKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let key = SigningKey::from_bytes(&[0x42; 32]);
    let verifying_key = key.verifying_key();
    let _ = nazo_operator_protocol::protected_header(&input);
    let _ = nazo_operator_protocol::verify_task(&input, "fuzz-controller", &verifying_key, 0);
    let _ = nazo_operator_protocol::verify_runtime_receipt(
        &input,
        "fuzz-runtime",
        &verifying_key,
    );
    let _ = nazo_operator_protocol::verify_final_receipt(
        &input,
        "fuzz-controller",
        &verifying_key,
    );
    let _ = nazo_operator_protocol::verify_trust_transition(
        &input,
        "fuzz-controller",
        &verifying_key,
    );
    let _ = nazo_operator_protocol::verify_management_event(
        &input,
        "fuzz-controller",
        &verifying_key,
    );
});
