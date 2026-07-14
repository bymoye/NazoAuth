use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

use nazo_auth::{SignError, SignRequest, Signature, Signer, SigningPurpose};

struct FakeSigner;

impl Signer for FakeSigner {
    async fn sign(&self, request: SignRequest<'_>) -> Result<Signature, SignError> {
        assert_eq!(request.purpose, SigningPurpose::Jarm);
        assert_eq!(request.algorithm, "EdDSA");
        assert_eq!(request.signing_input, b"header.payload");
        Ok(Signature::new(vec![0x01, 0x02, 0x03]))
    }
}

fn poll_ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = pin!(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("test fake must complete without a runtime"),
    }
}

#[test]
fn signer_receives_only_purpose_scoped_signing_material() {
    let signature = poll_ready(FakeSigner.sign(SignRequest {
        purpose: SigningPurpose::Jarm,
        algorithm: "EdDSA",
        signing_input: b"header.payload",
    }))
    .unwrap();

    assert_eq!(signature.as_bytes(), &[0x01, 0x02, 0x03]);
}
