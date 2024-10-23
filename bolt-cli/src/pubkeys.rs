use ethereum_consensus::crypto::bls::{PublicKey as BlsPublicKey, SecretKey as BlsSecretKey};
use eyre::Result;
use lighthouse_eth2_keystore::Keystore;

use crate::utils::keystore::{keystore_paths, KeystoreError, KeystoreSecret};

/// Derive public keys from the provided secret keys.
pub fn list_from_local_keys(secret_keys: &[String]) -> Result<Vec<BlsPublicKey>> {
    let mut pubkeys = Vec::with_capacity(secret_keys.len());

    for sk in secret_keys {
        let sk = BlsSecretKey::try_from(sk.trim().to_string())?;
        pubkeys.push(sk.public_key());
    }

    Ok(pubkeys)
}

/// Derive public keys from the keystore files in the provided directory.
pub fn list_from_keystore(
    keys_path: &str,
    keystore_secret: KeystoreSecret,
) -> Result<Vec<BlsPublicKey>> {
    let keystores_paths = keystore_paths(keys_path)?;
    let mut pubkeys = Vec::with_capacity(keystores_paths.len());

    for path in keystores_paths {
        let ks = Keystore::from_json_file(path).map_err(KeystoreError::Eth2Keystore)?;
        let password = keystore_secret.get(ks.pubkey()).ok_or(KeystoreError::MissingPassword)?;
        let kp = ks.decrypt_keypair(password.as_bytes()).map_err(KeystoreError::Eth2Keystore)?;
        let pubkey = BlsPublicKey::try_from(kp.pk.serialize().to_vec().as_ref())?;
        pubkeys.push(pubkey);
    }

    Ok(pubkeys)
}
