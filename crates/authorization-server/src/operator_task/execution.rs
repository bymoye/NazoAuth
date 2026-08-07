use super::*;

pub(super) async fn execute(operation: &TaskOperation) -> TaskOutcome {
    let result = match operation {
        TaskOperation::MigrateApply => crate::cli::run_migrations()
            .await
            .map(|applied| TaskResult::Migration { applied }),
        TaskOperation::ConformanceLeaseCreate {
            profile,
            material_sha256,
            dynamic_registration_initial_access_token_sha256,
            ciba_automated_decision_token_sha256,
            public_material,
            ttl_seconds,
        } => {
            crate::conformance_lease::operator_create(
                profile,
                material_sha256,
                dynamic_registration_initial_access_token_sha256.as_deref(),
                ciba_automated_decision_token_sha256.as_deref(),
                public_material.clone(),
                *ttl_seconds,
            )
            .await
        }
        TaskOperation::ConformanceLeaseList => crate::conformance_lease::operator_list().await,
        TaskOperation::ConformanceLeaseRevoke { lease_id } => {
            crate::conformance_lease::operator_revoke(lease_id).await
        }
        TaskOperation::ConformanceLeaseCleanup => {
            crate::conformance_lease::operator_cleanup().await
        }
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
    };
    match result {
        Ok(result) => TaskOutcome::Succeeded { result },
        Err(error) => TaskOutcome::Failed {
            code: stable_error_code(&error),
        },
    }
}
