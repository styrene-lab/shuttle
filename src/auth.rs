use ed25519_dalek::SigningKey;
use russh_keys::key::KeyPair;
use std::sync::Arc;
use styrene_identity::derive::KeyDeriver;
use styrene_identity::signer::{RootSecret, SignerError};
use zeroize::Zeroize;

/// Derive an SSH key pair for a given identity label.
///
/// Uses two-level HKDF: root_secret → ssh-user-master → per-label Ed25519 seed.
/// The seed exists in memory only during key construction and is zeroized after.
pub fn derive_key_pair(root: &RootSecret, label: &str) -> Result<Arc<KeyPair>, AuthError> {
    let deriver = KeyDeriver::new(root.as_bytes());
    let mut seed = deriver
        .derive_ssh_user_key(label)
        .map_err(|e| AuthError::Derivation(e.to_string()))?;
    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(Arc::new(KeyPair::Ed25519(signing_key)))
}

/// Derive the public key bytes for a label (for fingerprint display, authorized_keys export).
pub fn derive_public_key_bytes(root: &RootSecret, label: &str) -> Result<[u8; 32], AuthError> {
    let deriver = KeyDeriver::new(root.as_bytes());
    let mut seed = deriver
        .derive_ssh_user_key(label)
        .map_err(|e| AuthError::Derivation(e.to_string()))?;
    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    let verifying_key = signing_key.verifying_key();
    Ok(verifying_key.to_bytes())
}

/// Compute a hex fingerprint of the public key for display.
pub fn public_key_fingerprint(root: &RootSecret, label: &str) -> Result<String, AuthError> {
    let pubkey_bytes = derive_public_key_bytes(root, label)?;
    Ok(hex::encode(pubkey_bytes))
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("key derivation failed: {0}")]
    Derivation(String),
    #[error("signer error: {0}")]
    Signer(#[from] SignerError),
    #[error("authentication rejected by server")]
    Rejected,
}
