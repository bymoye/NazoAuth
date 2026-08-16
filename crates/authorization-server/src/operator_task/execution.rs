use super::*;

pub(super) async fn execute_with_jti(operation: &TaskOperation, _task_jti: &str) -> TaskOutcome {
    let result = match operation {
        TaskOperation::MigrateApply => crate::cli::run_migrations()
            .await
            .map(|applied| TaskResult::Migration { applied }),
        TaskOperation::KeysList => crate::keyctl::operator_list()
            .await
            .map(|keyset_revision| TaskResult::KeyList { keyset_revision }),
        TaskOperation::KeysValidate => crate::keyctl::operator_validate()
            .await
            .map(|keyset_revision| TaskResult::KeyValidation { keyset_revision }),
        TaskOperation::KeysGenerateLocal { alg, purposes } => {
            crate::keyctl::operator_generate_local(alg, purposes)
                .await
                .map(|(kid, keyset_revision)| TaskResult::KeyGenerated {
                    kid,
                    keyset_revision,
                })
        }
        TaskOperation::KeysRegisterExternal {
            kid,
            alg,
            key_ref,
            public_jwk_sha256,
        } => match verify_public_jwk(public_jwk_sha256) {
            Ok(path) => crate::keyctl::operator_register_external(kid, alg, key_ref, path)
                .await
                .map(|keyset_revision| TaskResult::ExternalKeyRegistered {
                    kid: kid.clone(),
                    keyset_revision,
                }),
            Err(error) => Err(error),
        },
        // Old signed envelopes remain deserializable in the shared protocol so
        // deployed controllers can archive their receipts. The server has no
        // Suite implementation behind any unsupported operation.
        _ => Err(anyhow::anyhow!("unsupported operator operation")),
    };
    match result {
        Ok(result) => TaskOutcome::Succeeded { result },
        Err(error) => TaskOutcome::Failed {
            code: stable_error_code(&error),
        },
    }
}
