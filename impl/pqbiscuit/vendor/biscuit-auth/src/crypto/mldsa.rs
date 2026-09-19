/*
 * Post-quantum backend for Biscuit: ML-DSA-44 (FIPS 204, Dilithium level 2).
 *
 * This backend is added for the post-quantum migration study. It reuses the
 * audited PQClean implementation through the `pqcrypto-dilithium` crate and
 * plugs into Biscuit's existing per-algorithm crypto abstraction exactly like
 * the `p256` backend.
 *
 * Design notes
 * ------------
 * * PQClean's ML-DSA secret-key encoding does **not** embed the public key
 *   (the verification key `t_1` is not part of the FIPS 204 secret key).
 *   Biscuit's attenuable (unsealed) proof carries the next block's *secret*
 *   key, and on append the holder must recover the matching public key that is
 *   bound into the signed block (`nextKey`). We therefore serialise an
 *   ML-DSA private key inside Biscuit as `secret_key || public_key`. This only
 *   affects the (already larger) attenuable proof; sealed tokens carry a final
 *   signature and never embed a secret key.
 * * Keys are stored as fixed-size byte arrays so that the wrapper types
 *   satisfy the same `Copy`/`Clone`/`PartialEq`/`Eq`/`Hash` derives the outer
 *   crypto enums require, without depending on whether the pqcrypto newtypes
 *   implement them.
 * * PEM/DER encoding is not provided for PQ keys in this prototype; the
 *   methods exist (gated on the `pem` feature) only to satisfy the exhaustive
 *   matches in the outer abstraction and return an explicit error.
 */
use std::fmt;

use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::sign::{
    DetachedSignature as DSigTrait, PublicKey as PKtrait, SecretKey as SKtrait,
};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use super::Signature;
use crate::error;

/// ML-DSA-44 public-key length in bytes (FIPS 204).
pub(crate) const PK_LEN: usize = 1312;
/// ML-DSA-44 secret-key length in bytes (FIPS 204).
pub(crate) const SK_LEN: usize = 2560;

const ALG_NAME: &str = "mldsa44";

fn invalid_key_size(len: usize) -> error::Format {
    error::Format::InvalidKeySize(len)
}

#[cfg(feature = "pem")]
fn pem_unsupported() -> error::Format {
    error::Format::InvalidKey(
        "ML-DSA-44 keys do not support PEM/DER encoding in the post-quantum prototype"
            .to_string(),
    )
}

/// ML-DSA-44 signing keypair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPair {
    pub(crate) sk: [u8; SK_LEN],
    pub(crate) pk: [u8; PK_LEN],
}

impl KeyPair {
    pub(crate) fn new_with_rng<R: RngCore + CryptoRng>(_rng: &mut R) -> Self {
        // pqcrypto draws randomness through its internal (getrandom-backed) RNG;
        // the supplied RNG is unused but kept for API symmetry with the other backends.
        let (pk, sk) = dilithium2::keypair();
        debug_assert_eq!(dilithium2::public_key_bytes(), PK_LEN);
        debug_assert_eq!(dilithium2::secret_key_bytes(), SK_LEN);

        let mut sk_arr = [0u8; SK_LEN];
        sk_arr.copy_from_slice(sk.as_bytes());
        let mut pk_arr = [0u8; PK_LEN];
        pk_arr.copy_from_slice(pk.as_bytes());
        KeyPair {
            sk: sk_arr,
            pk: pk_arr,
        }
    }

    pub(crate) fn from(key: &PrivateKey) -> Self {
        KeyPair {
            sk: key.sk,
            pk: key.pk,
        }
    }

    /// Rebuilds a keypair from the Biscuit PQ private-key encoding `sk || pk`.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, error::Format> {
        if bytes.len() != SK_LEN + PK_LEN {
            return Err(invalid_key_size(bytes.len()));
        }
        let mut sk = [0u8; SK_LEN];
        sk.copy_from_slice(&bytes[..SK_LEN]);
        let mut pk = [0u8; PK_LEN];
        pk.copy_from_slice(&bytes[SK_LEN..]);

        // Validate both halves against PQClean before accepting them.
        dilithium2::SecretKey::from_bytes(&sk).map_err(|_| invalid_key_size(SK_LEN))?;
        dilithium2::PublicKey::from_bytes(&pk).map_err(|_| invalid_key_size(PK_LEN))?;

        Ok(KeyPair { sk, pk })
    }

    pub(crate) fn sign(&self, data: &[u8]) -> Result<Signature, error::Format> {
        let sk = dilithium2::SecretKey::from_bytes(&self.sk).map_err(|_| invalid_key_size(SK_LEN))?;
        let signature = dilithium2::detached_sign(data, &sk);
        Ok(Signature(signature.as_bytes().to_vec()))
    }

    pub(crate) fn private(&self) -> PrivateKey {
        PrivateKey {
            sk: self.sk,
            pk: self.pk,
        }
    }

    pub(crate) fn public(&self) -> PublicKey {
        PublicKey(self.pk)
    }

    #[cfg(feature = "pem")]
    pub(crate) fn from_private_key_der(bytes: &[u8]) -> Result<Self, error::Format> {
        let _ = bytes;
        Err(pem_unsupported())
    }

    #[cfg(feature = "pem")]
    pub(crate) fn from_private_key_pem(str: &str) -> Result<Self, error::Format> {
        let _ = str;
        Err(pem_unsupported())
    }

    #[cfg(feature = "pem")]
    pub(crate) fn to_private_key_der(&self) -> Result<Zeroizing<Vec<u8>>, error::Format> {
        Err(pem_unsupported())
    }

    #[cfg(feature = "pem")]
    pub(crate) fn to_private_key_pem(&self) -> Result<Zeroizing<String>, error::Format> {
        Err(pem_unsupported())
    }
}

/// ML-DSA-44 private key, stored as `sk || pk`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKey {
    pub(crate) sk: [u8; SK_LEN],
    pub(crate) pk: [u8; PK_LEN],
}

impl PrivateKey {
    /// Serialises to the Biscuit PQ private-key encoding `sk || pk`.
    pub(crate) fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Vec::with_capacity(SK_LEN + PK_LEN);
        bytes.extend_from_slice(&self.sk);
        bytes.extend_from_slice(&self.pk);
        Zeroizing::new(bytes)
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, error::Format> {
        if bytes.len() != SK_LEN + PK_LEN {
            return Err(invalid_key_size(bytes.len()));
        }
        let mut sk = [0u8; SK_LEN];
        sk.copy_from_slice(&bytes[..SK_LEN]);
        let mut pk = [0u8; PK_LEN];
        pk.copy_from_slice(&bytes[SK_LEN..]);

        dilithium2::SecretKey::from_bytes(&sk).map_err(|_| invalid_key_size(SK_LEN))?;
        dilithium2::PublicKey::from_bytes(&pk).map_err(|_| invalid_key_size(PK_LEN))?;

        Ok(PrivateKey { sk, pk })
    }

    pub(crate) fn public(&self) -> PublicKey {
        PublicKey(self.pk)
    }

    #[cfg(feature = "pem")]
    pub(crate) fn from_der(bytes: &[u8]) -> Result<Self, error::Format> {
        let _ = bytes;
        Err(pem_unsupported())
    }

    #[cfg(feature = "pem")]
    pub(crate) fn from_pem(str: &str) -> Result<Self, error::Format> {
        let _ = str;
        Err(pem_unsupported())
    }

    #[cfg(feature = "pem")]
    pub(crate) fn to_der(&self) -> Result<Zeroizing<Vec<u8>>, error::Format> {
        Err(pem_unsupported())
    }

    #[cfg(feature = "pem")]
    pub(crate) fn to_pem(&self) -> Result<Zeroizing<String>, error::Format> {
        Err(pem_unsupported())
    }
}

/// ML-DSA-44 public (verification) key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(pub(crate) [u8; PK_LEN]);

impl PublicKey {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, error::Format> {
        if bytes.len() != PK_LEN {
            return Err(invalid_key_size(bytes.len()));
        }
        let pk = dilithium2::PublicKey::from_bytes(bytes).map_err(|_| invalid_key_size(PK_LEN))?;
        let mut arr = [0u8; PK_LEN];
        arr.copy_from_slice(pk.as_bytes());
        Ok(PublicKey(arr))
    }

    pub(crate) fn verify_signature(
        &self,
        data: &[u8],
        signature: &Signature,
    ) -> Result<(), error::Format> {
        let pk = dilithium2::PublicKey::from_bytes(&self.0).map_err(|_| invalid_key_size(PK_LEN))?;
        let sig = dilithium2::DetachedSignature::from_bytes(&signature.0)
            .map_err(|_| error::Format::InvalidSignatureSize(signature.0.len()))?;
        dilithium2::verify_detached_signature(&sig, data, &pk).map_err(|_| {
            error::Format::Signature(error::Signature::InvalidSignature(
                "ML-DSA-44 signature verification failed".to_string(),
            ))
        })
    }

    pub(crate) fn write(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{ALG_NAME}/{}", hex::encode(self.0))
    }

    pub(crate) fn print(&self) -> String {
        format!("{ALG_NAME}/{}", hex::encode(self.0))
    }

    #[cfg(feature = "pem")]
    pub(crate) fn from_der(bytes: &[u8]) -> Result<Self, error::Format> {
        let _ = bytes;
        Err(pem_unsupported())
    }

    #[cfg(feature = "pem")]
    pub(crate) fn from_pem(str: &str) -> Result<Self, error::Format> {
        let _ = str;
        Err(pem_unsupported())
    }

    #[cfg(feature = "pem")]
    pub(crate) fn to_der(&self) -> Result<Vec<u8>, error::Format> {
        Err(pem_unsupported())
    }

    #[cfg(feature = "pem")]
    pub(crate) fn to_pem(&self) -> Result<String, error::Format> {
        Err(pem_unsupported())
    }
}
