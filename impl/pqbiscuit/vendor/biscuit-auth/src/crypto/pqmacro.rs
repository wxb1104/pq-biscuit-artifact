/*
 * Shared post-quantum signature backend for Biscuit.
 *
 * The `pq_backend!` macro generates the three wrapper types
 * (`KeyPair` / `PrivateKey` / `PublicKey`) and all conversions for one
 * pqcrypto/​PQClean signature parameter set. It is the parameterised form of
 * the hand-written and tested ML-DSA-44 backend in `mldsa.rs`, so adding
 * ML-DSA-65/87, FN-DSA-512/1024 (variable-length signatures) and
 * SLH-DSA (stateless hash-based, large signatures) is a one-line invocation.
 *
 * The design constraints are identical to `mldsa.rs`:
 *  * PQClean secret keys do not necessarily embed the public key, while the
 *    attenuable proof carries the next block's secret key and the holder must
 *    recover the matching `nextKey`. Private keys are therefore serialised as
 *    `secret_key || public_key`. This only affects the (already larger)
 *    attenuable proof; sealed tokens carry only a final signature.
 *  * Keys are fixed-size byte arrays so the wrappers satisfy the outer enums'
 *    `Copy`/`Clone`/`PartialEq`/`Eq`/`Hash` derives regardless of whether the
 *    pqcrypto newtypes implement them.
 *  * Signatures are returned as `Vec<u8>` (the outer `Signature` is already a
 *    `Vec`), which transparently accommodates FN-DSA's variable-length
 *    signatures; `DetachedSignature::from_bytes` accepts up to the parameter
 *    set's capacity.
 *  * PEM/DER is not provided for PQ keys; the gated methods exist only to
 *    satisfy the outer exhaustive matches and return an explicit error.
 */
#[macro_export] // visible as crate::pq_backend within this crate
#[doc(hidden)]
macro_rules! pq_backend {
    ($module:path, $pk_len:literal, $sk_len:literal, $alg_name:literal, $display:literal) => {
        use std::fmt;

        use $module as pq;
        use pqcrypto_traits::sign::{
            DetachedSignature as DSigTrait, PublicKey as PKtrait, SecretKey as SKtrait,
        };
        use rand_core::{CryptoRng, RngCore};
        use zeroize::Zeroizing;

        use super::Signature;
        use crate::error;

        /// Public-key length in bytes.
        pub(crate) const PK_LEN: usize = $pk_len;
        /// Secret-key length in bytes (PQClean encoding).
        pub(crate) const SK_LEN: usize = $sk_len;

        const ALG_NAME: &str = $alg_name;

        fn invalid_key_size(len: usize) -> error::Format {
            error::Format::InvalidKeySize(len)
        }

        #[cfg(feature = "pem")]
        fn pem_unsupported() -> error::Format {
            error::Format::InvalidKey(format!(
                "{} keys do not support PEM/DER encoding in the post-quantum prototype",
                $display
            ))
        }

        /// Post-quantum signing keypair.
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct KeyPair {
            pub(crate) sk: [u8; SK_LEN],
            pub(crate) pk: [u8; PK_LEN],
        }

        impl KeyPair {
            pub(crate) fn new_with_rng<R: RngCore + CryptoRng>(_rng: &mut R) -> Self {
                // pqcrypto draws randomness through its internal (getrandom-backed) RNG.
                let (pk, sk) = pq::keypair();
                debug_assert_eq!(pq::public_key_bytes(), PK_LEN);
                debug_assert_eq!(pq::secret_key_bytes(), SK_LEN);

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

                pq::SecretKey::from_bytes(&sk).map_err(|_| invalid_key_size(SK_LEN))?;
                pq::PublicKey::from_bytes(&pk).map_err(|_| invalid_key_size(PK_LEN))?;

                Ok(KeyPair { sk, pk })
            }

            pub(crate) fn sign(&self, data: &[u8]) -> Result<Signature, error::Format> {
                let sk = pq::SecretKey::from_bytes(&self.sk)
                    .map_err(|_| invalid_key_size(SK_LEN))?;
                let signature = pq::detached_sign(data, &sk);
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
            pub(crate) fn to_private_key_der(
                &self,
            ) -> Result<Zeroizing<Vec<u8>>, error::Format> {
                Err(pem_unsupported())
            }

            #[cfg(feature = "pem")]
            pub(crate) fn to_private_key_pem(
                &self,
            ) -> Result<Zeroizing<String>, error::Format> {
                Err(pem_unsupported())
            }
        }

        /// Post-quantum private key, stored as `sk || pk`.
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

                pq::SecretKey::from_bytes(&sk).map_err(|_| invalid_key_size(SK_LEN))?;
                pq::PublicKey::from_bytes(&pk).map_err(|_| invalid_key_size(PK_LEN))?;

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

        /// Post-quantum public (verification) key.
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
                let pk =
                    pq::PublicKey::from_bytes(bytes).map_err(|_| invalid_key_size(PK_LEN))?;
                let mut arr = [0u8; PK_LEN];
                arr.copy_from_slice(pk.as_bytes());
                Ok(PublicKey(arr))
            }

            pub(crate) fn verify_signature(
                &self,
                data: &[u8],
                signature: &Signature,
            ) -> Result<(), error::Format> {
                let pk = pq::PublicKey::from_bytes(&self.0)
                    .map_err(|_| invalid_key_size(PK_LEN))?;
                let sig = pq::DetachedSignature::from_bytes(&signature.0)
                    .map_err(|_| error::Format::InvalidSignatureSize(signature.0.len()))?;
                pq::verify_detached_signature(&sig, data, &pk).map_err(|_| {
                    error::Format::Signature(error::Signature::InvalidSignature(format!(
                        "{} signature verification failed",
                        $display
                    )))
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
    };
}
