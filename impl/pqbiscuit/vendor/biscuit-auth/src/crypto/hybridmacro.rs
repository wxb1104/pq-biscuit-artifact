/*
 * Labelled strong-nesting hybrid signature backend for Biscuit.
 *
 * This macro generates a hybrid backend that binds a classical Ed25519
 * signature (inner, Σ1) and a post-quantum signature (outer, Σ2) using the
 * construction H(Σ1,Σ2) of Ghinea et al. (OpenSK, eprint 2022/1225, §4),
 * which is Bindel et al.'s (PQCrypto 2017, §4.2) strong-nesting combiner
 * Cstr-nest with the §4.4 domain-separation labels:
 *
 *     m0   = L1 || m
 *     σ1   = Ed25519.Sign(sk_ed, m0)
 *     σ2   = PQ.Sign(sk_pq, L2 || enc(m0) || enc(σ1))      // enc = u32be(len)||x
 *     σ    = σ1 || σ2                                      // σ1 is exactly 64 B
 *
 *     Verify = Ed25519.Verify(pk_ed, m0, σ1)
 *              ∧ PQ.Verify(pk_pq, L2||enc(m0)||enc(σ1), σ2)
 *
 * L1,L2 are fixed 32-byte SHA-256 domain-separation constants that name both
 * algorithms and the construction, so a component signature cannot be lifted
 * and accepted as a stand-alone signature in another context (1-/2-non-
 * separability; Bindel Thm. 8, OpenSK Def. 4). Security is by citation of the
 * combiner theorems; no new security argument is introduced here.
 *
 * The first argument is the module identifier (under crate::crypto) of a
 * pq_backend!-generated post-quantum backend, e.g. `mldsa` or `fndsa512`.
 */
#[macro_export]
#[doc(hidden)]
macro_rules! hybrid_backend {
    ($pqmod:ident, $pk_len:literal, $sk_len:literal, $alg_name:literal,
     $display:literal, $label_seed:literal) => {
        use sha2::{Digest, Sha256};

        use super::Signature;
        use crate::crypto::ed25519::{
            KeyPair as EdKeyPair, PrivateKey as EdPrivateKey, PublicKey as EdPublicKey,
        };
        use crate::error;

        const ED_SK_LEN: usize = 32;
        const ED_PK_LEN: usize = 32;
        const ED_SIG_LEN: usize = 64;
        pub(crate) const PK_LEN: usize = ED_PK_LEN + $pk_len;
        pub(crate) const SK_LEN: usize = ED_SK_LEN + $sk_len + $pk_len;

        const ALG_NAME: &str = $alg_name;

        /// digest 0.9 API (biscuit-auth pins sha2 = "^0.9")
        fn sha256_bytes(data: &[u8]) -> [u8; 32] {
            let r = Sha256::digest(data);
            let mut out = [0u8; 32];
            out.copy_from_slice(&r);
            out
        }

        fn labels() -> ([u8; 32], [u8; 32]) {
            let l1 = sha256_bytes(&[$label_seed.as_bytes(), b"|m0"].concat());
            let l2 = sha256_bytes(&[$label_seed.as_bytes(), b"|nest"].concat());
            (l1, l2)
        }

        /// canonical u32 big-endian length-prefix encoding (unambiguous tuple)
        fn enc(out: &mut Vec<u8>, x: &[u8]) {
            out.extend_from_slice(&(x.len() as u32).to_be_bytes());
            out.extend_from_slice(x);
        }

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

        fn m0_of(data: &[u8]) -> Vec<u8> {
            let (l1, _) = labels();
            let mut m0 = Vec::with_capacity(32 + data.len());
            m0.extend_from_slice(&l1);
            m0.extend_from_slice(data);
            m0
        }

        fn nest_of(m0: &[u8], sig1: &[u8]) -> Vec<u8> {
            let (_, l2) = labels();
            let mut nest = Vec::with_capacity(32 + 4 + m0.len() + 4 + sig1.len());
            nest.extend_from_slice(&l2);
            enc(&mut nest, m0);
            enc(&mut nest, sig1);
            nest
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct KeyPair {
            pub(crate) ed_sk: [u8; ED_SK_LEN],
            pub(crate) pq_sk: [u8; $sk_len],
            pub(crate) pq_pk: [u8; $pk_len],
        }

        impl KeyPair {
            pub(crate) fn new_with_rng<R: rand_core::RngCore + rand_core::CryptoRng>(
                rng: &mut R,
            ) -> Self {
                let ed = EdKeyPair::new_with_rng(rng);
                let pq = crate::crypto::$pqmod::KeyPair::new_with_rng(rng);
                KeyPair {
                    ed_sk: ed.private().0,
                    pq_sk: pq.sk,
                    pq_pk: pq.pk,
                }
            }

            pub(crate) fn from(key: &PrivateKey) -> Self {
                KeyPair {
                    ed_sk: key.ed_sk,
                    pq_sk: key.pq_sk,
                    pq_pk: key.pq_pk,
                }
            }

            /// Ed secret (32) || PQ secret ($sk_len) || PQ public ($pk_len)
            pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, error::Format> {
                if bytes.len() != SK_LEN {
                    return Err(invalid_key_size(bytes.len()));
                }
                let ed = EdKeyPair::from_bytes(&bytes[..ED_SK_LEN])?;
                let pq = crate::crypto::$pqmod::KeyPair::from_bytes(&bytes[ED_SK_LEN..])?;
                Ok(KeyPair {
                    ed_sk: ed.private().0,
                    pq_sk: pq.sk,
                    pq_pk: pq.pk,
                })
            }

            pub(crate) fn sign(&self, data: &[u8]) -> Result<Signature, error::Format> {
                let m0 = m0_of(data);
                let ed = EdKeyPair::from_bytes(&self.ed_sk)?;
                let sig1 = ed.sign(&m0)?.0;

                let mut pq_bytes = Vec::with_capacity($sk_len + $pk_len);
                pq_bytes.extend_from_slice(&self.pq_sk);
                pq_bytes.extend_from_slice(&self.pq_pk);
                let pq = crate::crypto::$pqmod::KeyPair::from_bytes(&pq_bytes)?;
                let nest = nest_of(&m0, &sig1);
                let sig2 = pq.sign(&nest)?.0;

                let mut out = Vec::with_capacity(sig1.len() + sig2.len());
                out.extend_from_slice(&sig1);
                out.extend_from_slice(&sig2);
                Ok(Signature(out))
            }

            pub(crate) fn private(&self) -> PrivateKey {
                PrivateKey {
                    ed_sk: self.ed_sk,
                    pq_sk: self.pq_sk,
                    pq_pk: self.pq_pk,
                }
            }

            pub(crate) fn public(&self) -> PublicKey {
                let ed_pk = EdKeyPair::from_bytes(&self.ed_sk)
                    .expect("valid ed secret")
                    .public()
                    .to_bytes();
                PublicKey {
                    ed_pk,
                    pq_pk: self.pq_pk,
                }
            }

            #[cfg(feature = "pem")]
            pub(crate) fn from_private_key_der(b: &[u8]) -> Result<Self, error::Format> {
                let _ = b;
                Err(pem_unsupported())
            }
            #[cfg(feature = "pem")]
            pub(crate) fn from_private_key_pem(s: &str) -> Result<Self, error::Format> {
                let _ = s;
                Err(pem_unsupported())
            }
            #[cfg(feature = "pem")]
            pub(crate) fn to_private_key_der(
                &self,
            ) -> Result<zeroize::Zeroizing<Vec<u8>>, error::Format> {
                Err(pem_unsupported())
            }
            #[cfg(feature = "pem")]
            pub(crate) fn to_private_key_pem(
                &self,
            ) -> Result<zeroize::Zeroizing<String>, error::Format> {
                Err(pem_unsupported())
            }
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct PrivateKey {
            pub(crate) ed_sk: [u8; ED_SK_LEN],
            pub(crate) pq_sk: [u8; $sk_len],
            pub(crate) pq_pk: [u8; $pk_len],
        }

        impl PrivateKey {
            pub(crate) fn to_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
                let mut b = Vec::with_capacity(SK_LEN);
                b.extend_from_slice(&self.ed_sk);
                b.extend_from_slice(&self.pq_sk);
                b.extend_from_slice(&self.pq_pk);
                zeroize::Zeroizing::new(b)
            }

            pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, error::Format> {
                if bytes.len() != SK_LEN {
                    return Err(invalid_key_size(bytes.len()));
                }
                let ed = EdPrivateKey::from_bytes(&bytes[..ED_SK_LEN])?;
                let pq = crate::crypto::$pqmod::PrivateKey::from_bytes(&bytes[ED_SK_LEN..])?;
                Ok(PrivateKey {
                    ed_sk: ed.0,
                    pq_sk: pq.sk,
                    pq_pk: pq.pk,
                })
            }

            pub(crate) fn public(&self) -> PublicKey {
                let ed_pk = EdPrivateKey::from_bytes(&self.ed_sk)
                    .expect("valid ed secret")
                    .public()
                    .to_bytes();
                PublicKey {
                    ed_pk,
                    pq_pk: self.pq_pk,
                }
            }

            #[cfg(feature = "pem")]
            pub(crate) fn from_der(b: &[u8]) -> Result<Self, error::Format> {
                let _ = b;
                Err(pem_unsupported())
            }
            #[cfg(feature = "pem")]
            pub(crate) fn from_pem(s: &str) -> Result<Self, error::Format> {
                let _ = s;
                Err(pem_unsupported())
            }
            #[cfg(feature = "pem")]
            pub(crate) fn to_der(
                &self,
            ) -> Result<zeroize::Zeroizing<Vec<u8>>, error::Format> {
                Err(pem_unsupported())
            }
            #[cfg(feature = "pem")]
            pub(crate) fn to_pem(
                &self,
            ) -> Result<zeroize::Zeroizing<String>, error::Format> {
                Err(pem_unsupported())
            }
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct PublicKey {
            pub(crate) ed_pk: [u8; ED_PK_LEN],
            pub(crate) pq_pk: [u8; $pk_len],
        }

        impl PublicKey {
            pub(crate) fn to_bytes(&self) -> Vec<u8> {
                let mut b = Vec::with_capacity(PK_LEN);
                b.extend_from_slice(&self.ed_pk);
                b.extend_from_slice(&self.pq_pk);
                b
            }

            pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, error::Format> {
                if bytes.len() != PK_LEN {
                    return Err(invalid_key_size(bytes.len()));
                }
                let ed = EdPublicKey::from_bytes(&bytes[..ED_PK_LEN])?;
                let pq = crate::crypto::$pqmod::PublicKey::from_bytes(&bytes[ED_PK_LEN..])?;
                Ok(PublicKey {
                    ed_pk: ed.to_bytes(),
                    pq_pk: pq.0,
                })
            }

            pub(crate) fn verify_signature(
                &self,
                data: &[u8],
                signature: &Signature,
            ) -> Result<(), error::Format> {
                if signature.0.len() < ED_SIG_LEN {
                    return Err(error::Format::InvalidSignatureSize(signature.0.len()));
                }
                let sig1 = &signature.0[..ED_SIG_LEN];
                let sig2 = &signature.0[ED_SIG_LEN..];

                let m0 = m0_of(data);
                let ed = EdPublicKey::from_bytes(&self.ed_pk)?;
                ed.verify_signature(&m0, &Signature(sig1.to_vec()))?;

                let nest = nest_of(&m0, sig1);
                let pq = crate::crypto::$pqmod::PublicKey(self.pq_pk);
                pq.verify_signature(&nest, &Signature(sig2.to_vec()))?;
                Ok(())
            }

            pub(crate) fn write(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{ALG_NAME}/{}", hex::encode(self.to_bytes()))
            }

            pub(crate) fn print(&self) -> String {
                format!("{ALG_NAME}/{}", hex::encode(self.to_bytes()))
            }

            #[cfg(feature = "pem")]
            pub(crate) fn from_der(b: &[u8]) -> Result<Self, error::Format> {
                let _ = b;
                Err(pem_unsupported())
            }
            #[cfg(feature = "pem")]
            pub(crate) fn from_pem(s: &str) -> Result<Self, error::Format> {
                let _ = s;
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

        #[cfg(test)]
        mod hybrid_combiner_tests {
            use super::*;

            #[test]
            fn labelled_strong_nesting_correctness_and_binding() {
                let mut rng = rand::rngs::OsRng;
                let kp = KeyPair::new_with_rng(&mut rng);
                let pk = kp.public();
                let data: Vec<u8> = b"block payload".to_vec();
                let sig = kp.sign(&data).unwrap();

                // correctness: full hybrid verification accepts
                pk.verify_signature(&data, &sig).unwrap();

                // wrong message rejected
                assert!(pk.verify_signature(b"tampered", &sig).is_err());

                // tamper inner Ed component σ1 -> rejected
                let mut s1 = sig.0.clone();
                s1[10] ^= 0x01;
                assert!(pk.verify_signature(&data, &Signature(s1)).is_err());

                // tamper outer PQ component σ2 -> rejected
                let mut s2 = sig.0.clone();
                let idx = s2.len() - 5;
                s2[idx] ^= 0x01;
                assert!(pk.verify_signature(&data, &Signature(s2)).is_err());

                // non-separation / domain separation: σ1 must NOT be accepted
                // as a stand-alone Ed25519 signature over the *raw* message ...
                let sig1 = sig.0[..ED_SIG_LEN].to_vec();
                let ed = EdPublicKey::from_bytes(&pk.ed_pk).unwrap();
                assert!(ed.verify_signature(&data, &Signature(sig1.clone())).is_err());
                // ... but it does verify over L1||m, i.e. it is bound inside the
                // labelled construction and cannot be lifted out of context.
                let m0 = m0_of(&data);
                ed.verify_signature(&m0, &Signature(sig1)).unwrap();

                // secret/public key byte round-trips
                let sk_bytes = kp.private().to_bytes();
                let kp2 = KeyPair::from_bytes(&sk_bytes).unwrap();
                assert_eq!(kp2.public().to_bytes(), pk.to_bytes());
                let pk_bytes = pk.to_bytes();
                assert_eq!(
                    PublicKey::from_bytes(&pk_bytes).unwrap().to_bytes(),
                    pk_bytes
                );
                assert_eq!(pk_bytes.len(), PK_LEN);
                assert_eq!(sk_bytes.len(), SK_LEN);
            }
        }
    };
}
