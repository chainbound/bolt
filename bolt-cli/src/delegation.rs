use ethereum_consensus::crypto::{
    PublicKey as BlsPublicKey, SecretKey as BlsSecretKey, Signature as BlsSignature,
};
use eyre::Result;
use lighthouse_eth2_keystore::Keystore;

use crate::{
    config::{Action, Chain},
    types::{
        DelegationMessage, RevocationMessage, SignedDelegation, SignedMessage, SignedRevocation,
    },
    utils::{
        keystore::{keystore_paths, KeystoreError, KeystoreSecret},
        signing::compute_commit_boost_signing_root,
    },
};

/// Generate signed delegations/revocations using local BLS private keys
///
/// - Use the provided private keys from either CLI or env variable
/// - Create message
/// - Compute the signing roots and sign the messages
/// - Return the signed messages
pub fn generate_from_local_keys(
    secret_keys: &Vec<String>,
    delegatee_pubkey: BlsPublicKey,
    chain: &Chain,
    action: Action,
) -> Result<Vec<SignedMessage>> {
    let mut signed_messages = Vec::with_capacity(secret_keys.len());

    for sk in secret_keys {
        let sk = BlsSecretKey::try_from(sk.trim().to_string())?;

        match action {
            Action::Delegate => {
                let message = DelegationMessage::new(sk.public_key(), delegatee_pubkey.clone());
                let signing_root = compute_commit_boost_signing_root(message.digest(), chain)?;
                let signature = sk.sign(signing_root.0.as_ref());
                let signed = SignedDelegation { message, signature };
                signed_messages.push(SignedMessage::Delegation(signed))
            }
            Action::Revoke => {
                let message = RevocationMessage::new(sk.public_key(), delegatee_pubkey.clone());
                let signing_root = compute_commit_boost_signing_root(message.digest(), chain)?;
                let signature = sk.sign(signing_root.0.as_ref());
                let signed = SignedRevocation { message, signature };
                signed_messages.push(SignedMessage::Revocation(signed));
            }
        }
    }

    Ok(signed_messages)
}

/// Generate signed delegations/revocations using a keystore file
///
/// - Read the keystore file
/// - Decrypt the keypairs using the password
/// - Create messages
/// - Compute the signing roots and sign the message
/// - Return the signed message
pub fn generate_from_keystore(
    keys_path: &str,
    keystore_secret: KeystoreSecret,
    delegatee_pubkey: BlsPublicKey,
    chain: Chain,
    action: Action,
) -> Result<Vec<SignedMessage>> {
    let keystores_paths = keystore_paths(keys_path)?;
    let mut signed_messages = Vec::with_capacity(keystores_paths.len());

    for path in keystores_paths {
        let ks = Keystore::from_json_file(path).map_err(KeystoreError::Eth2Keystore)?;
        let password = keystore_secret.get(ks.pubkey()).ok_or(KeystoreError::MissingPassword)?;
        let kp = ks.decrypt_keypair(password.as_bytes()).map_err(KeystoreError::Eth2Keystore)?;
        let validator_pubkey = BlsPublicKey::try_from(kp.pk.serialize().to_vec().as_ref())?;
        let validator_private_key = kp.sk;

        match action {
            Action::Delegate => {
                let message = DelegationMessage::new(validator_pubkey, delegatee_pubkey.clone());
                let signing_root = compute_commit_boost_signing_root(message.digest(), &chain)?;
                let signature = validator_private_key.sign(signing_root.0.into());
                let signature = BlsSignature::try_from(signature.serialize().as_ref())?;
                let signed = SignedDelegation { message, signature };
                signed_messages.push(SignedMessage::Delegation(signed));
            }
            Action::Revoke => {
                let message = RevocationMessage::new(validator_pubkey, delegatee_pubkey.clone());
                let signing_root = compute_commit_boost_signing_root(message.digest(), &chain)?;
                let signature = validator_private_key.sign(signing_root.0.into());
                let signature = BlsSignature::try_from(signature.serialize().as_ref())?;
                let signed = SignedRevocation { message, signature };
                signed_messages.push(SignedMessage::Revocation(signed));
            }
        }
    }

    Ok(signed_messages)
}

#[cfg(test)]
mod tests {
    use ethereum_consensus::crypto::PublicKey as BlsPublicKey;

    use crate::{
        config::{Action, Chain},
        types::SignedMessage,
        utils::{keystore::KeystoreSecret, parse_public_key, signing::verify_commit_boost_root},
    };

    use super::generate_from_keystore;

    #[test]
    fn test_delegation_keystore_signer_lighthouse() -> eyre::Result<()> {
        // Read the keystore from test_data
        let keys_path = env!("CARGO_MANIFEST_DIR").to_string() + "/test_data/lighthouse/validators";
        let secrets_path = env!("CARGO_MANIFEST_DIR").to_string() + "/test_data/lighthouse/secrets";

        let keystore_secret = KeystoreSecret::from_directory(secrets_path)?;

        let delegatee_pubkey = "0x83eeddfac5e60f8fe607ee8713efb8877c295ad9f8ca075f4d8f6f2ae241a30dd57f78f6f3863a9fe0d5b5db9d550b93";
        let delegatee_pubkey = parse_public_key(delegatee_pubkey)?;
        let chain = Chain::Mainnet;

        let signed_delegations = generate_from_keystore(
            &keys_path,
            keystore_secret,
            delegatee_pubkey.clone(),
            chain,
            Action::Delegate,
        )?;

        let signed_message = signed_delegations.first().expect("to get signed delegation");

        verify_delegation_signature(signed_message, delegatee_pubkey, chain);

        Ok(())
    }

    fn verify_delegation_signature(
        message: &SignedMessage,
        delegatee_pubkey: BlsPublicKey,
        chain: Chain,
    ) {
        match message {
            SignedMessage::Delegation(signed_delegation) => {
                let output_delegatee_pubkey = signed_delegation.message.delegatee_pubkey.clone();
                let signer_pubkey = signed_delegation.message.validator_pubkey.clone();
                let digest = signed_delegation.message.digest();
                assert_eq!(output_delegatee_pubkey, delegatee_pubkey);

                let blst_sig =
                    blst::min_pk::Signature::from_bytes(signed_delegation.signature.as_ref())
                        .expect("Failed to convert delegation signature");

                // Verify the signature
                assert!(verify_commit_boost_root(signer_pubkey, digest, &blst_sig, &chain).is_ok());
            }
            _ => panic!("Expected a delegation message"),
        }
    }
}
