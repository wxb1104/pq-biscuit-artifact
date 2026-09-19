/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
//! cryptographic operations
//!
//! Biscuit tokens are based on a chain of Ed25519 signatures.
//! This provides the fundamental operation for offline delegation: from a message
//! and a valid signature, it is possible to add a new message and produce a valid
//! signature for the whole.
//!
//! The implementation is based on [ed25519_dalek](https://github.com/dalek-cryptography/ed25519-dalek).
#![allow(non_snake_case)]
use crate::builder::Algorithm;
use crate::format::schema;
use crate::format::ThirdPartyVerificationMode;

use super::error;
mod ed25519;
mod mldsa;
mod pqmacro;
mod mldsa65;
mod mldsa87;
mod fndsa512;
mod fndsa1024;
mod slhdsa128s;
mod slhdsa128f;
mod slhdsa256s;
mod slhdsa256f;
mod hybridmacro;
mod hybrid_ed_mldsa44;
mod hybrid_ed_fndsa512;
mod p256;

use nom::Finish;
use rand_core::{CryptoRng, RngCore};
use std::fmt;
use std::hash::Hash;
use std::str::FromStr;

/// pair of cryptographic keys used to sign a token's block
#[derive(Debug, PartialEq)]
pub enum KeyPair {
    Ed25519(ed25519::KeyPair),
    Mldsa44(mldsa::KeyPair),
    Mldsa65(mldsa65::KeyPair),
    Mldsa87(mldsa87::KeyPair),
    Fndsa512(fndsa512::KeyPair),
    Fndsa1024(fndsa1024::KeyPair),
    Slhdsa128s(slhdsa128s::KeyPair),
    Slhdsa128f(slhdsa128f::KeyPair),
    Slhdsa256s(slhdsa256s::KeyPair),
    Slhdsa256f(slhdsa256f::KeyPair),
    HybridEdMldsa44(hybrid_ed_mldsa44::KeyPair),
    HybridEdFndsa512(hybrid_ed_fndsa512::KeyPair),
    P256(p256::KeyPair),
}

impl KeyPair {
    /// Create a new ed25519 keypair with the default OS RNG
    pub fn new() -> Self {
        Self::new_with_rng(Algorithm::Ed25519, &mut rand::rngs::OsRng)
    }

    /// Create a new keypair with a chosen algorithm and the default OS RNG
    pub fn new_with_algorithm(algorithm: Algorithm) -> Self {
        Self::new_with_rng(algorithm, &mut rand::rngs::OsRng)
    }

    pub fn new_with_rng<T: RngCore + CryptoRng>(algorithm: Algorithm, rng: &mut T) -> Self {
        match algorithm {
            Algorithm::Ed25519 => KeyPair::Ed25519(ed25519::KeyPair::new_with_rng(rng)),
            Algorithm::Mldsa44 => KeyPair::Mldsa44(mldsa::KeyPair::new_with_rng(rng)),
            Algorithm::Mldsa65 => KeyPair::Mldsa65(mldsa65::KeyPair::new_with_rng(rng)),
            Algorithm::Mldsa87 => KeyPair::Mldsa87(mldsa87::KeyPair::new_with_rng(rng)),
            Algorithm::Fndsa512 => KeyPair::Fndsa512(fndsa512::KeyPair::new_with_rng(rng)),
            Algorithm::Fndsa1024 => KeyPair::Fndsa1024(fndsa1024::KeyPair::new_with_rng(rng)),
            Algorithm::Slhdsa128s => KeyPair::Slhdsa128s(slhdsa128s::KeyPair::new_with_rng(rng)),
            Algorithm::Slhdsa128f => KeyPair::Slhdsa128f(slhdsa128f::KeyPair::new_with_rng(rng)),
            Algorithm::Slhdsa256s => KeyPair::Slhdsa256s(slhdsa256s::KeyPair::new_with_rng(rng)),
            Algorithm::Slhdsa256f => KeyPair::Slhdsa256f(slhdsa256f::KeyPair::new_with_rng(rng)),
            Algorithm::HybridEdMldsa44 => KeyPair::HybridEdMldsa44(hybrid_ed_mldsa44::KeyPair::new_with_rng(rng)),
            Algorithm::HybridEdFndsa512 => KeyPair::HybridEdFndsa512(hybrid_ed_fndsa512::KeyPair::new_with_rng(rng)),
            Algorithm::Secp256r1 => KeyPair::P256(p256::KeyPair::new_with_rng(rng)),
        }
    }

    pub fn from(key: &PrivateKey) -> Self {
        match key {
            PrivateKey::Ed25519(key) => KeyPair::Ed25519(ed25519::KeyPair::from(key)),
            PrivateKey::Mldsa44(key) => KeyPair::Mldsa44(mldsa::KeyPair::from(key)),
            PrivateKey::Mldsa65(key) => KeyPair::Mldsa65(mldsa65::KeyPair::from(key)),
            PrivateKey::Mldsa87(key) => KeyPair::Mldsa87(mldsa87::KeyPair::from(key)),
            PrivateKey::Fndsa512(key) => KeyPair::Fndsa512(fndsa512::KeyPair::from(key)),
            PrivateKey::Fndsa1024(key) => KeyPair::Fndsa1024(fndsa1024::KeyPair::from(key)),
            PrivateKey::Slhdsa128s(key) => KeyPair::Slhdsa128s(slhdsa128s::KeyPair::from(key)),
            PrivateKey::Slhdsa128f(key) => KeyPair::Slhdsa128f(slhdsa128f::KeyPair::from(key)),
            PrivateKey::Slhdsa256s(key) => KeyPair::Slhdsa256s(slhdsa256s::KeyPair::from(key)),
            PrivateKey::Slhdsa256f(key) => KeyPair::Slhdsa256f(slhdsa256f::KeyPair::from(key)),
            PrivateKey::HybridEdMldsa44(key) => KeyPair::HybridEdMldsa44(hybrid_ed_mldsa44::KeyPair::from(key)),
            PrivateKey::HybridEdFndsa512(key) => KeyPair::HybridEdFndsa512(hybrid_ed_fndsa512::KeyPair::from(key)),
            PrivateKey::P256(key) => KeyPair::P256(p256::KeyPair::from(key)),
        }
    }

    /// deserializes from a byte array
    pub fn from_bytes(
        bytes: &[u8],
        algorithm: schema::public_key::Algorithm,
    ) -> Result<Self, error::Format> {
        match algorithm {
            schema::public_key::Algorithm::Ed25519 => {
                Ok(KeyPair::Ed25519(ed25519::KeyPair::from_bytes(bytes)?))
            }
            schema::public_key::Algorithm::Secp256r1 => {
                Ok(KeyPair::P256(p256::KeyPair::from_bytes(bytes)?))
            }
            schema::public_key::Algorithm::Mldsa44 => {
                Ok(KeyPair::Mldsa44(mldsa::KeyPair::from_bytes(bytes)?))
            }
            schema::public_key::Algorithm::Mldsa65 => {
                Ok(KeyPair::Mldsa65(mldsa65::KeyPair::from_bytes(bytes)?))
            }
            schema::public_key::Algorithm::Mldsa87 => {
                Ok(KeyPair::Mldsa87(mldsa87::KeyPair::from_bytes(bytes)?))
            }
            schema::public_key::Algorithm::Fndsa512 => {
                Ok(KeyPair::Fndsa512(fndsa512::KeyPair::from_bytes(bytes)?))
            }
            schema::public_key::Algorithm::Fndsa1024 => {
                Ok(KeyPair::Fndsa1024(fndsa1024::KeyPair::from_bytes(bytes)?))
            }
            schema::public_key::Algorithm::Slhdsa128s => {
                Ok(KeyPair::Slhdsa128s(slhdsa128s::KeyPair::from_bytes(bytes)?))
            }
            schema::public_key::Algorithm::Slhdsa128f => {
                Ok(KeyPair::Slhdsa128f(slhdsa128f::KeyPair::from_bytes(bytes)?))
            }
            schema::public_key::Algorithm::Slhdsa256s => {
                Ok(KeyPair::Slhdsa256s(slhdsa256s::KeyPair::from_bytes(bytes)?))
            }
            schema::public_key::Algorithm::Slhdsa256f => {
                Ok(KeyPair::Slhdsa256f(slhdsa256f::KeyPair::from_bytes(bytes)?))
            }
            schema::public_key::Algorithm::HybridEdMldsa44 => {
                Ok(KeyPair::HybridEdMldsa44(hybrid_ed_mldsa44::KeyPair::from_bytes(bytes)?))
            }
            schema::public_key::Algorithm::HybridEdFndsa512 => {
                Ok(KeyPair::HybridEdFndsa512(hybrid_ed_fndsa512::KeyPair::from_bytes(bytes)?))
            }
        }
    }

    pub fn sign(&self, data: &[u8]) -> Result<Signature, error::Format> {
        match self {
            KeyPair::Ed25519(key) => key.sign(data),
            KeyPair::Mldsa44(key) => key.sign(data),
            KeyPair::Mldsa65(key) => key.sign(data),
            KeyPair::Mldsa87(key) => key.sign(data),
            KeyPair::Fndsa512(key) => key.sign(data),
            KeyPair::Fndsa1024(key) => key.sign(data),
            KeyPair::Slhdsa128s(key) => key.sign(data),
            KeyPair::Slhdsa128f(key) => key.sign(data),
            KeyPair::Slhdsa256s(key) => key.sign(data),
            KeyPair::Slhdsa256f(key) => key.sign(data),
            KeyPair::HybridEdMldsa44(key) => key.sign(data),
            KeyPair::HybridEdFndsa512(key) => key.sign(data),
            KeyPair::P256(key) => key.sign(data),
        }
    }

    #[cfg(feature = "pem")]
    pub fn from_private_key_der_with_algorithm(
        bytes: &[u8],
        algorithm: Algorithm,
    ) -> Result<Self, error::Format> {
        match algorithm {
            Algorithm::Ed25519 => Ok(KeyPair::Ed25519(ed25519::KeyPair::from_private_key_der(
                bytes,
            )?)),
            Algorithm::Secp256r1 => Ok(KeyPair::P256(p256::KeyPair::from_private_key_der(bytes)?)),
            Algorithm::Mldsa44 => Ok(KeyPair::Mldsa44(mldsa::KeyPair::from_private_key_der(bytes)?)),
            Algorithm::Mldsa65 => Ok(KeyPair::Mldsa65(mldsa65::KeyPair::from_private_key_der(bytes)?)),
            Algorithm::Mldsa87 => Ok(KeyPair::Mldsa87(mldsa87::KeyPair::from_private_key_der(bytes)?)),
            Algorithm::Fndsa512 => Ok(KeyPair::Fndsa512(fndsa512::KeyPair::from_private_key_der(bytes)?)),
            Algorithm::Fndsa1024 => Ok(KeyPair::Fndsa1024(fndsa1024::KeyPair::from_private_key_der(bytes)?)),
            Algorithm::Slhdsa128s => Ok(KeyPair::Slhdsa128s(slhdsa128s::KeyPair::from_private_key_der(bytes)?)),
            Algorithm::Slhdsa128f => Ok(KeyPair::Slhdsa128f(slhdsa128f::KeyPair::from_private_key_der(bytes)?)),
            Algorithm::Slhdsa256s => Ok(KeyPair::Slhdsa256s(slhdsa256s::KeyPair::from_private_key_der(bytes)?)),
            Algorithm::Slhdsa256f => Ok(KeyPair::Slhdsa256f(slhdsa256f::KeyPair::from_private_key_der(bytes)?)),
            Algorithm::HybridEdMldsa44 => Ok(KeyPair::HybridEdMldsa44(hybrid_ed_mldsa44::KeyPair::from_private_key_der(bytes)?)),
            Algorithm::HybridEdFndsa512 => Ok(KeyPair::HybridEdFndsa512(hybrid_ed_fndsa512::KeyPair::from_private_key_der(bytes)?)),
        }
    }

    #[cfg(feature = "pem")]
    pub fn from_private_key_der(bytes: &[u8]) -> Result<Self, error::Format> {
        parse_any_algorithm(bytes, Self::from_private_key_der_with_algorithm)
    }

    #[cfg(feature = "pem")]
    pub fn from_private_key_pem_with_algorithm(
        str: &str,
        algorithm: Algorithm,
    ) -> Result<Self, error::Format> {
        match algorithm {
            Algorithm::Ed25519 => Ok(KeyPair::Ed25519(ed25519::KeyPair::from_private_key_pem(
                str,
            )?)),
            Algorithm::Secp256r1 => Ok(KeyPair::P256(p256::KeyPair::from_private_key_pem(str)?)),
            Algorithm::Mldsa44 => Ok(KeyPair::Mldsa44(mldsa::KeyPair::from_private_key_pem(str)?)),
            Algorithm::Mldsa65 => Ok(KeyPair::Mldsa65(mldsa65::KeyPair::from_private_key_pem(str)?)),
            Algorithm::Mldsa87 => Ok(KeyPair::Mldsa87(mldsa87::KeyPair::from_private_key_pem(str)?)),
            Algorithm::Fndsa512 => Ok(KeyPair::Fndsa512(fndsa512::KeyPair::from_private_key_pem(str)?)),
            Algorithm::Fndsa1024 => Ok(KeyPair::Fndsa1024(fndsa1024::KeyPair::from_private_key_pem(str)?)),
            Algorithm::Slhdsa128s => Ok(KeyPair::Slhdsa128s(slhdsa128s::KeyPair::from_private_key_pem(str)?)),
            Algorithm::Slhdsa128f => Ok(KeyPair::Slhdsa128f(slhdsa128f::KeyPair::from_private_key_pem(str)?)),
            Algorithm::Slhdsa256s => Ok(KeyPair::Slhdsa256s(slhdsa256s::KeyPair::from_private_key_pem(str)?)),
            Algorithm::Slhdsa256f => Ok(KeyPair::Slhdsa256f(slhdsa256f::KeyPair::from_private_key_pem(str)?)),
            Algorithm::HybridEdMldsa44 => Ok(KeyPair::HybridEdMldsa44(hybrid_ed_mldsa44::KeyPair::from_private_key_pem(str)?)),
            Algorithm::HybridEdFndsa512 => Ok(KeyPair::HybridEdFndsa512(hybrid_ed_fndsa512::KeyPair::from_private_key_pem(str)?)),
        }
    }

    #[cfg(feature = "pem")]
    pub fn from_private_key_pem(str: &str) -> Result<Self, error::Format> {
        parse_any_algorithm(str, Self::from_private_key_pem_with_algorithm)
    }

    #[cfg(feature = "pem")]
    pub fn to_private_key_der(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, error::Format> {
        match self {
            KeyPair::Ed25519(key) => key.to_private_key_der(),
            KeyPair::Mldsa44(key) => key.to_private_key_der(),
            KeyPair::Mldsa65(key) => key.to_private_key_der(),
            KeyPair::Mldsa87(key) => key.to_private_key_der(),
            KeyPair::Fndsa512(key) => key.to_private_key_der(),
            KeyPair::Fndsa1024(key) => key.to_private_key_der(),
            KeyPair::Slhdsa128s(key) => key.to_private_key_der(),
            KeyPair::Slhdsa128f(key) => key.to_private_key_der(),
            KeyPair::Slhdsa256s(key) => key.to_private_key_der(),
            KeyPair::Slhdsa256f(key) => key.to_private_key_der(),
            KeyPair::HybridEdMldsa44(key) => key.to_private_key_der(),
            KeyPair::HybridEdFndsa512(key) => key.to_private_key_der(),
            KeyPair::P256(key) => key.to_private_key_der(),
        }
    }

    #[cfg(feature = "pem")]
    pub fn to_private_key_pem(&self) -> Result<zeroize::Zeroizing<String>, error::Format> {
        match self {
            KeyPair::Ed25519(key) => key.to_private_key_pem(),
            KeyPair::Mldsa44(key) => key.to_private_key_pem(),
            KeyPair::Mldsa65(key) => key.to_private_key_pem(),
            KeyPair::Mldsa87(key) => key.to_private_key_pem(),
            KeyPair::Fndsa512(key) => key.to_private_key_pem(),
            KeyPair::Fndsa1024(key) => key.to_private_key_pem(),
            KeyPair::Slhdsa128s(key) => key.to_private_key_pem(),
            KeyPair::Slhdsa128f(key) => key.to_private_key_pem(),
            KeyPair::Slhdsa256s(key) => key.to_private_key_pem(),
            KeyPair::Slhdsa256f(key) => key.to_private_key_pem(),
            KeyPair::HybridEdMldsa44(key) => key.to_private_key_pem(),
            KeyPair::HybridEdFndsa512(key) => key.to_private_key_pem(),
            KeyPair::P256(key) => key.to_private_key_pem(),
        }
    }

    pub fn private(&self) -> PrivateKey {
        match self {
            KeyPair::Ed25519(key) => PrivateKey::Ed25519(key.private()),
            KeyPair::Mldsa44(key) => PrivateKey::Mldsa44(key.private()),
            KeyPair::Mldsa65(key) => PrivateKey::Mldsa65(key.private()),
            KeyPair::Mldsa87(key) => PrivateKey::Mldsa87(key.private()),
            KeyPair::Fndsa512(key) => PrivateKey::Fndsa512(key.private()),
            KeyPair::Fndsa1024(key) => PrivateKey::Fndsa1024(key.private()),
            KeyPair::Slhdsa128s(key) => PrivateKey::Slhdsa128s(key.private()),
            KeyPair::Slhdsa128f(key) => PrivateKey::Slhdsa128f(key.private()),
            KeyPair::Slhdsa256s(key) => PrivateKey::Slhdsa256s(key.private()),
            KeyPair::Slhdsa256f(key) => PrivateKey::Slhdsa256f(key.private()),
            KeyPair::HybridEdMldsa44(key) => PrivateKey::HybridEdMldsa44(key.private()),
            KeyPair::HybridEdFndsa512(key) => PrivateKey::HybridEdFndsa512(key.private()),
            KeyPair::P256(key) => PrivateKey::P256(key.private()),
        }
    }

    pub fn public(&self) -> PublicKey {
        match self {
            KeyPair::Ed25519(key) => PublicKey::Ed25519(key.public()),
            KeyPair::Mldsa44(key) => PublicKey::Mldsa44(key.public()),
            KeyPair::Mldsa65(key) => PublicKey::Mldsa65(key.public()),
            KeyPair::Mldsa87(key) => PublicKey::Mldsa87(key.public()),
            KeyPair::Fndsa512(key) => PublicKey::Fndsa512(key.public()),
            KeyPair::Fndsa1024(key) => PublicKey::Fndsa1024(key.public()),
            KeyPair::Slhdsa128s(key) => PublicKey::Slhdsa128s(key.public()),
            KeyPair::Slhdsa128f(key) => PublicKey::Slhdsa128f(key.public()),
            KeyPair::Slhdsa256s(key) => PublicKey::Slhdsa256s(key.public()),
            KeyPair::Slhdsa256f(key) => PublicKey::Slhdsa256f(key.public()),
            KeyPair::HybridEdMldsa44(key) => PublicKey::HybridEdMldsa44(key.public()),
            KeyPair::HybridEdFndsa512(key) => PublicKey::HybridEdFndsa512(key.public()),
            KeyPair::P256(key) => PublicKey::P256(key.public()),
        }
    }

    pub fn algorithm(&self) -> crate::format::schema::public_key::Algorithm {
        match self {
            KeyPair::Ed25519(_) => crate::format::schema::public_key::Algorithm::Ed25519,
            KeyPair::Mldsa44(_) => crate::format::schema::public_key::Algorithm::Mldsa44,
            KeyPair::Mldsa65(_) => crate::format::schema::public_key::Algorithm::Mldsa65,
            KeyPair::Mldsa87(_) => crate::format::schema::public_key::Algorithm::Mldsa87,
            KeyPair::Fndsa512(_) => crate::format::schema::public_key::Algorithm::Fndsa512,
            KeyPair::Fndsa1024(_) => crate::format::schema::public_key::Algorithm::Fndsa1024,
            KeyPair::Slhdsa128s(_) => crate::format::schema::public_key::Algorithm::Slhdsa128s,
            KeyPair::Slhdsa128f(_) => crate::format::schema::public_key::Algorithm::Slhdsa128f,
            KeyPair::Slhdsa256s(_) => crate::format::schema::public_key::Algorithm::Slhdsa256s,
            KeyPair::Slhdsa256f(_) => crate::format::schema::public_key::Algorithm::Slhdsa256f,
            KeyPair::HybridEdMldsa44(_) => crate::format::schema::public_key::Algorithm::HybridEdMldsa44,
            KeyPair::HybridEdFndsa512(_) => crate::format::schema::public_key::Algorithm::HybridEdFndsa512,
            KeyPair::P256(_) => crate::format::schema::public_key::Algorithm::Secp256r1,
        }
    }
}

impl std::default::Default for KeyPair {
    fn default() -> Self {
        Self::new()
    }
}

/// the private part of a [KeyPair]
#[derive(Debug, Clone, PartialEq)]
pub enum PrivateKey {
    Ed25519(ed25519::PrivateKey),
    Mldsa44(mldsa::PrivateKey),
    Mldsa65(mldsa65::PrivateKey),
    Mldsa87(mldsa87::PrivateKey),
    Fndsa512(fndsa512::PrivateKey),
    Fndsa1024(fndsa1024::PrivateKey),
    Slhdsa128s(slhdsa128s::PrivateKey),
    Slhdsa128f(slhdsa128f::PrivateKey),
    Slhdsa256s(slhdsa256s::PrivateKey),
    Slhdsa256f(slhdsa256f::PrivateKey),
    HybridEdMldsa44(hybrid_ed_mldsa44::PrivateKey),
    HybridEdFndsa512(hybrid_ed_fndsa512::PrivateKey),
    P256(p256::PrivateKey),
}

impl FromStr for PrivateKey {
    type Err = error::Format;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once('/') {
            Some(("ed25519-private", bytes)) => Self::from_bytes_hex(bytes, Algorithm::Ed25519),
            Some(("secp256r1-private", bytes)) => Self::from_bytes_hex(bytes, Algorithm::Secp256r1),
            Some(("mldsa44-private", bytes)) => Self::from_bytes_hex(bytes, Algorithm::Mldsa44),
            Some(("mldsa65-private", bytes)) => Self::from_bytes_hex(bytes, Algorithm::Mldsa65),
            Some(("mldsa87-private", bytes)) => Self::from_bytes_hex(bytes, Algorithm::Mldsa87),
            Some(("fndsa512-private", bytes)) => Self::from_bytes_hex(bytes, Algorithm::Fndsa512),
            Some(("fndsa1024-private", bytes)) => Self::from_bytes_hex(bytes, Algorithm::Fndsa1024),
            Some(("slhdsa128s-private", bytes)) => Self::from_bytes_hex(bytes, Algorithm::Slhdsa128s),
            Some(("slhdsa128f-private", bytes)) => Self::from_bytes_hex(bytes, Algorithm::Slhdsa128f),
            Some(("slhdsa256s-private", bytes)) => Self::from_bytes_hex(bytes, Algorithm::Slhdsa256s),
            Some(("slhdsa256f-private", bytes)) => Self::from_bytes_hex(bytes, Algorithm::Slhdsa256f),
            Some(("hybrid-ed-mldsa44-private", bytes)) => Self::from_bytes_hex(bytes, Algorithm::HybridEdMldsa44),
            Some(("hybrid-ed-fndsa512-private", bytes)) => Self::from_bytes_hex(bytes, Algorithm::HybridEdFndsa512),
            Some((alg, _)) => Err(error::Format::InvalidKey(format!(
                "Unsupported key algorithm {alg}"
            ))),
            None => Err(error::Format::InvalidKey(
                "Missing key algorithm".to_string(),
            )),
        }
    }
}

impl PrivateKey {
    /// serializes to a byte array
    pub fn to_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        match self {
            PrivateKey::Ed25519(key) => zeroize::Zeroizing::new(key.to_bytes()),
            PrivateKey::Mldsa44(key) => key.to_bytes(),
            PrivateKey::Mldsa65(key) => key.to_bytes(),
            PrivateKey::Mldsa87(key) => key.to_bytes(),
            PrivateKey::Fndsa512(key) => key.to_bytes(),
            PrivateKey::Fndsa1024(key) => key.to_bytes(),
            PrivateKey::Slhdsa128s(key) => key.to_bytes(),
            PrivateKey::Slhdsa128f(key) => key.to_bytes(),
            PrivateKey::Slhdsa256s(key) => key.to_bytes(),
            PrivateKey::Slhdsa256f(key) => key.to_bytes(),
            PrivateKey::HybridEdMldsa44(key) => key.to_bytes(),
            PrivateKey::HybridEdFndsa512(key) => key.to_bytes(),
            PrivateKey::P256(key) => key.to_bytes(),
        }
    }

    /// serializes to an hex-encoded string
    pub fn to_bytes_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// serializes to an hex-encoded string, prefixed with the key algorithm
    pub fn to_prefixed_string(&self) -> String {
        let algorithm = match self.algorithm() {
            schema::public_key::Algorithm::Ed25519 => "ed25519-private",
            schema::public_key::Algorithm::Secp256r1 => "secp256r1-private",
            schema::public_key::Algorithm::Mldsa44 => "mldsa44-private",
            schema::public_key::Algorithm::Mldsa65 => "mldsa65-private",
            schema::public_key::Algorithm::Mldsa87 => "mldsa87-private",
            schema::public_key::Algorithm::Fndsa512 => "fndsa512-private",
            schema::public_key::Algorithm::Fndsa1024 => "fndsa1024-private",
            schema::public_key::Algorithm::Slhdsa128s => "slhdsa128s-private",
            schema::public_key::Algorithm::Slhdsa128f => "slhdsa128f-private",
            schema::public_key::Algorithm::Slhdsa256s => "slhdsa256s-private",
            schema::public_key::Algorithm::Slhdsa256f => "slhdsa256f-private",
            schema::public_key::Algorithm::HybridEdMldsa44 => "hybrid-ed-mldsa44-private",
            schema::public_key::Algorithm::HybridEdFndsa512 => "hybrid-ed-fndsa512-private",
        };
        format!("{algorithm}/{}", self.to_bytes_hex())
    }

    /// deserializes from a byte array
    pub fn from_bytes(bytes: &[u8], algorithm: Algorithm) -> Result<Self, error::Format> {
        match algorithm {
            Algorithm::Ed25519 => Ok(PrivateKey::Ed25519(ed25519::PrivateKey::from_bytes(bytes)?)),
            Algorithm::Mldsa44 => Ok(PrivateKey::Mldsa44(mldsa::PrivateKey::from_bytes(bytes)?)),
            Algorithm::Mldsa65 => Ok(PrivateKey::Mldsa65(mldsa65::PrivateKey::from_bytes(bytes)?)),
            Algorithm::Mldsa87 => Ok(PrivateKey::Mldsa87(mldsa87::PrivateKey::from_bytes(bytes)?)),
            Algorithm::Fndsa512 => Ok(PrivateKey::Fndsa512(fndsa512::PrivateKey::from_bytes(bytes)?)),
            Algorithm::Fndsa1024 => Ok(PrivateKey::Fndsa1024(fndsa1024::PrivateKey::from_bytes(bytes)?)),
            Algorithm::Slhdsa128s => Ok(PrivateKey::Slhdsa128s(slhdsa128s::PrivateKey::from_bytes(bytes)?)),
            Algorithm::Slhdsa128f => Ok(PrivateKey::Slhdsa128f(slhdsa128f::PrivateKey::from_bytes(bytes)?)),
            Algorithm::Slhdsa256s => Ok(PrivateKey::Slhdsa256s(slhdsa256s::PrivateKey::from_bytes(bytes)?)),
            Algorithm::Slhdsa256f => Ok(PrivateKey::Slhdsa256f(slhdsa256f::PrivateKey::from_bytes(bytes)?)),
            Algorithm::HybridEdMldsa44 => Ok(PrivateKey::HybridEdMldsa44(hybrid_ed_mldsa44::PrivateKey::from_bytes(bytes)?)),
            Algorithm::HybridEdFndsa512 => Ok(PrivateKey::HybridEdFndsa512(hybrid_ed_fndsa512::PrivateKey::from_bytes(bytes)?)),
            Algorithm::Secp256r1 => Ok(PrivateKey::P256(p256::PrivateKey::from_bytes(bytes)?)),
        }
    }

    /// deserializes from an hex-encoded string
    pub fn from_bytes_hex(str: &str, algorithm: Algorithm) -> Result<Self, error::Format> {
        let bytes = hex::decode(str).map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Self::from_bytes(&bytes, algorithm)
    }

    #[cfg(feature = "pem")]
    pub fn from_der_with_algorithm(
        bytes: &[u8],
        algorithm: Algorithm,
    ) -> Result<Self, error::Format> {
        match algorithm {
            Algorithm::Ed25519 => Ok(PrivateKey::Ed25519(ed25519::PrivateKey::from_der(bytes)?)),
            Algorithm::Mldsa44 => Ok(PrivateKey::Mldsa44(mldsa::PrivateKey::from_der(bytes)?)),
            Algorithm::Mldsa65 => Ok(PrivateKey::Mldsa65(mldsa65::PrivateKey::from_der(bytes)?)),
            Algorithm::Mldsa87 => Ok(PrivateKey::Mldsa87(mldsa87::PrivateKey::from_der(bytes)?)),
            Algorithm::Fndsa512 => Ok(PrivateKey::Fndsa512(fndsa512::PrivateKey::from_der(bytes)?)),
            Algorithm::Fndsa1024 => Ok(PrivateKey::Fndsa1024(fndsa1024::PrivateKey::from_der(bytes)?)),
            Algorithm::Slhdsa128s => Ok(PrivateKey::Slhdsa128s(slhdsa128s::PrivateKey::from_der(bytes)?)),
            Algorithm::Slhdsa128f => Ok(PrivateKey::Slhdsa128f(slhdsa128f::PrivateKey::from_der(bytes)?)),
            Algorithm::Slhdsa256s => Ok(PrivateKey::Slhdsa256s(slhdsa256s::PrivateKey::from_der(bytes)?)),
            Algorithm::Slhdsa256f => Ok(PrivateKey::Slhdsa256f(slhdsa256f::PrivateKey::from_der(bytes)?)),
            Algorithm::HybridEdMldsa44 => Ok(PrivateKey::HybridEdMldsa44(hybrid_ed_mldsa44::PrivateKey::from_der(bytes)?)),
            Algorithm::HybridEdFndsa512 => Ok(PrivateKey::HybridEdFndsa512(hybrid_ed_fndsa512::PrivateKey::from_der(bytes)?)),
            Algorithm::Secp256r1 => Ok(PrivateKey::P256(p256::PrivateKey::from_der(bytes)?)),
        }
    }

    #[cfg(feature = "pem")]
    pub fn from_der(bytes: &[u8]) -> Result<Self, error::Format> {
        parse_any_algorithm(bytes, Self::from_der_with_algorithm)
    }

    #[cfg(feature = "pem")]
    pub fn from_pem_with_algorithm(str: &str, algorithm: Algorithm) -> Result<Self, error::Format> {
        match algorithm {
            Algorithm::Ed25519 => Ok(PrivateKey::Ed25519(ed25519::PrivateKey::from_pem(str)?)),
            Algorithm::Mldsa44 => Ok(PrivateKey::Mldsa44(mldsa::PrivateKey::from_pem(str)?)),
            Algorithm::Mldsa65 => Ok(PrivateKey::Mldsa65(mldsa65::PrivateKey::from_pem(str)?)),
            Algorithm::Mldsa87 => Ok(PrivateKey::Mldsa87(mldsa87::PrivateKey::from_pem(str)?)),
            Algorithm::Fndsa512 => Ok(PrivateKey::Fndsa512(fndsa512::PrivateKey::from_pem(str)?)),
            Algorithm::Fndsa1024 => Ok(PrivateKey::Fndsa1024(fndsa1024::PrivateKey::from_pem(str)?)),
            Algorithm::Slhdsa128s => Ok(PrivateKey::Slhdsa128s(slhdsa128s::PrivateKey::from_pem(str)?)),
            Algorithm::Slhdsa128f => Ok(PrivateKey::Slhdsa128f(slhdsa128f::PrivateKey::from_pem(str)?)),
            Algorithm::Slhdsa256s => Ok(PrivateKey::Slhdsa256s(slhdsa256s::PrivateKey::from_pem(str)?)),
            Algorithm::Slhdsa256f => Ok(PrivateKey::Slhdsa256f(slhdsa256f::PrivateKey::from_pem(str)?)),
            Algorithm::HybridEdMldsa44 => Ok(PrivateKey::HybridEdMldsa44(hybrid_ed_mldsa44::PrivateKey::from_pem(str)?)),
            Algorithm::HybridEdFndsa512 => Ok(PrivateKey::HybridEdFndsa512(hybrid_ed_fndsa512::PrivateKey::from_pem(str)?)),
            Algorithm::Secp256r1 => Ok(PrivateKey::P256(p256::PrivateKey::from_pem(str)?)),
        }
    }

    #[cfg(feature = "pem")]
    pub fn from_pem(str: &str) -> Result<Self, error::Format> {
        parse_any_algorithm(str, Self::from_pem_with_algorithm)
    }

    #[cfg(feature = "pem")]
    pub fn to_der(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, error::Format> {
        match self {
            PrivateKey::Ed25519(key) => key.to_der(),
            PrivateKey::Mldsa44(key) => key.to_der(),
            PrivateKey::Mldsa65(key) => key.to_der(),
            PrivateKey::Mldsa87(key) => key.to_der(),
            PrivateKey::Fndsa512(key) => key.to_der(),
            PrivateKey::Fndsa1024(key) => key.to_der(),
            PrivateKey::Slhdsa128s(key) => key.to_der(),
            PrivateKey::Slhdsa128f(key) => key.to_der(),
            PrivateKey::Slhdsa256s(key) => key.to_der(),
            PrivateKey::Slhdsa256f(key) => key.to_der(),
            PrivateKey::HybridEdMldsa44(key) => key.to_der(),
            PrivateKey::HybridEdFndsa512(key) => key.to_der(),
            PrivateKey::P256(key) => key.to_der(),
        }
    }

    #[cfg(feature = "pem")]
    pub fn to_pem(&self) -> Result<zeroize::Zeroizing<String>, error::Format> {
        match self {
            PrivateKey::Ed25519(key) => key.to_pem(),
            PrivateKey::Mldsa44(key) => key.to_pem(),
            PrivateKey::Mldsa65(key) => key.to_pem(),
            PrivateKey::Mldsa87(key) => key.to_pem(),
            PrivateKey::Fndsa512(key) => key.to_pem(),
            PrivateKey::Fndsa1024(key) => key.to_pem(),
            PrivateKey::Slhdsa128s(key) => key.to_pem(),
            PrivateKey::Slhdsa128f(key) => key.to_pem(),
            PrivateKey::Slhdsa256s(key) => key.to_pem(),
            PrivateKey::Slhdsa256f(key) => key.to_pem(),
            PrivateKey::HybridEdMldsa44(key) => key.to_pem(),
            PrivateKey::HybridEdFndsa512(key) => key.to_pem(),
            PrivateKey::P256(key) => key.to_pem(),
        }
    }

    /// returns the matching public key
    pub fn public(&self) -> PublicKey {
        match self {
            PrivateKey::Ed25519(key) => PublicKey::Ed25519(key.public()),
            PrivateKey::Mldsa44(key) => PublicKey::Mldsa44(key.public()),
            PrivateKey::Mldsa65(key) => PublicKey::Mldsa65(key.public()),
            PrivateKey::Mldsa87(key) => PublicKey::Mldsa87(key.public()),
            PrivateKey::Fndsa512(key) => PublicKey::Fndsa512(key.public()),
            PrivateKey::Fndsa1024(key) => PublicKey::Fndsa1024(key.public()),
            PrivateKey::Slhdsa128s(key) => PublicKey::Slhdsa128s(key.public()),
            PrivateKey::Slhdsa128f(key) => PublicKey::Slhdsa128f(key.public()),
            PrivateKey::Slhdsa256s(key) => PublicKey::Slhdsa256s(key.public()),
            PrivateKey::Slhdsa256f(key) => PublicKey::Slhdsa256f(key.public()),
            PrivateKey::HybridEdMldsa44(key) => PublicKey::HybridEdMldsa44(key.public()),
            PrivateKey::HybridEdFndsa512(key) => PublicKey::HybridEdFndsa512(key.public()),
            PrivateKey::P256(key) => PublicKey::P256(key.public()),
        }
    }

    pub fn algorithm(&self) -> crate::format::schema::public_key::Algorithm {
        match self {
            PrivateKey::Ed25519(_) => crate::format::schema::public_key::Algorithm::Ed25519,
            PrivateKey::Mldsa44(_) => crate::format::schema::public_key::Algorithm::Mldsa44,
            PrivateKey::Mldsa65(_) => crate::format::schema::public_key::Algorithm::Mldsa65,
            PrivateKey::Mldsa87(_) => crate::format::schema::public_key::Algorithm::Mldsa87,
            PrivateKey::Fndsa512(_) => crate::format::schema::public_key::Algorithm::Fndsa512,
            PrivateKey::Fndsa1024(_) => crate::format::schema::public_key::Algorithm::Fndsa1024,
            PrivateKey::Slhdsa128s(_) => crate::format::schema::public_key::Algorithm::Slhdsa128s,
            PrivateKey::Slhdsa128f(_) => crate::format::schema::public_key::Algorithm::Slhdsa128f,
            PrivateKey::Slhdsa256s(_) => crate::format::schema::public_key::Algorithm::Slhdsa256s,
            PrivateKey::Slhdsa256f(_) => crate::format::schema::public_key::Algorithm::Slhdsa256f,
            PrivateKey::HybridEdMldsa44(_) => crate::format::schema::public_key::Algorithm::HybridEdMldsa44,
            PrivateKey::HybridEdFndsa512(_) => crate::format::schema::public_key::Algorithm::HybridEdFndsa512,
            PrivateKey::P256(_) => crate::format::schema::public_key::Algorithm::Secp256r1,
        }
    }
}

/// the public part of a [KeyPair]
#[derive(Debug, Clone, Copy, PartialEq, Hash, Eq)]
pub enum PublicKey {
    Ed25519(ed25519::PublicKey),
    Mldsa44(mldsa::PublicKey),
    Mldsa65(mldsa65::PublicKey),
    Mldsa87(mldsa87::PublicKey),
    Fndsa512(fndsa512::PublicKey),
    Fndsa1024(fndsa1024::PublicKey),
    Slhdsa128s(slhdsa128s::PublicKey),
    Slhdsa128f(slhdsa128f::PublicKey),
    Slhdsa256s(slhdsa256s::PublicKey),
    Slhdsa256f(slhdsa256f::PublicKey),
    HybridEdMldsa44(hybrid_ed_mldsa44::PublicKey),
    HybridEdFndsa512(hybrid_ed_fndsa512::PublicKey),
    P256(p256::PublicKey),
}

impl PublicKey {
    /// serializes to a byte array
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PublicKey::Ed25519(key) => key.to_bytes().into(),
            PublicKey::Mldsa44(key) => key.to_bytes(),
            PublicKey::Mldsa65(key) => key.to_bytes(),
            PublicKey::Mldsa87(key) => key.to_bytes(),
            PublicKey::Fndsa512(key) => key.to_bytes(),
            PublicKey::Fndsa1024(key) => key.to_bytes(),
            PublicKey::Slhdsa128s(key) => key.to_bytes(),
            PublicKey::Slhdsa128f(key) => key.to_bytes(),
            PublicKey::Slhdsa256s(key) => key.to_bytes(),
            PublicKey::Slhdsa256f(key) => key.to_bytes(),
            PublicKey::HybridEdMldsa44(key) => key.to_bytes(),
            PublicKey::HybridEdFndsa512(key) => key.to_bytes(),
            PublicKey::P256(key) => key.to_bytes(),
        }
    }

    /// serializes to an hex-encoded string
    pub fn to_bytes_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// deserializes from a byte array
    pub fn from_bytes(bytes: &[u8], algorithm: Algorithm) -> Result<Self, error::Format> {
        match algorithm {
            Algorithm::Ed25519 => Ok(PublicKey::Ed25519(ed25519::PublicKey::from_bytes(bytes)?)),
            Algorithm::Mldsa44 => Ok(PublicKey::Mldsa44(mldsa::PublicKey::from_bytes(bytes)?)),
            Algorithm::Mldsa65 => Ok(PublicKey::Mldsa65(mldsa65::PublicKey::from_bytes(bytes)?)),
            Algorithm::Mldsa87 => Ok(PublicKey::Mldsa87(mldsa87::PublicKey::from_bytes(bytes)?)),
            Algorithm::Fndsa512 => Ok(PublicKey::Fndsa512(fndsa512::PublicKey::from_bytes(bytes)?)),
            Algorithm::Fndsa1024 => Ok(PublicKey::Fndsa1024(fndsa1024::PublicKey::from_bytes(bytes)?)),
            Algorithm::Slhdsa128s => Ok(PublicKey::Slhdsa128s(slhdsa128s::PublicKey::from_bytes(bytes)?)),
            Algorithm::Slhdsa128f => Ok(PublicKey::Slhdsa128f(slhdsa128f::PublicKey::from_bytes(bytes)?)),
            Algorithm::Slhdsa256s => Ok(PublicKey::Slhdsa256s(slhdsa256s::PublicKey::from_bytes(bytes)?)),
            Algorithm::Slhdsa256f => Ok(PublicKey::Slhdsa256f(slhdsa256f::PublicKey::from_bytes(bytes)?)),
            Algorithm::HybridEdMldsa44 => Ok(PublicKey::HybridEdMldsa44(hybrid_ed_mldsa44::PublicKey::from_bytes(bytes)?)),
            Algorithm::HybridEdFndsa512 => Ok(PublicKey::HybridEdFndsa512(hybrid_ed_fndsa512::PublicKey::from_bytes(bytes)?)),
            Algorithm::Secp256r1 => Ok(PublicKey::P256(p256::PublicKey::from_bytes(bytes)?)),
        }
    }

    /// deserializes from an hex-encoded string
    pub fn from_bytes_hex(str: &str, algorithm: Algorithm) -> Result<Self, error::Format> {
        let bytes = hex::decode(str).map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Self::from_bytes(&bytes, algorithm)
    }

    pub fn from_proto(key: &schema::PublicKey) -> Result<Self, error::Format> {
        if key.algorithm == schema::public_key::Algorithm::Ed25519 as i32 {
            Ok(PublicKey::Ed25519(ed25519::PublicKey::from_bytes(
                &key.key,
            )?))
        } else if key.algorithm == schema::public_key::Algorithm::Secp256r1 as i32 {
            Ok(PublicKey::P256(p256::PublicKey::from_bytes(&key.key)?))
        } else if key.algorithm == schema::public_key::Algorithm::Mldsa44 as i32 {
            Ok(PublicKey::Mldsa44(mldsa::PublicKey::from_bytes(&key.key)?))
        } else if key.algorithm == schema::public_key::Algorithm::Mldsa65 as i32 {
            Ok(PublicKey::Mldsa65(mldsa65::PublicKey::from_bytes(&key.key)?))
        } else if key.algorithm == schema::public_key::Algorithm::Mldsa87 as i32 {
            Ok(PublicKey::Mldsa87(mldsa87::PublicKey::from_bytes(&key.key)?))
        } else if key.algorithm == schema::public_key::Algorithm::Fndsa512 as i32 {
            Ok(PublicKey::Fndsa512(fndsa512::PublicKey::from_bytes(&key.key)?))
        } else if key.algorithm == schema::public_key::Algorithm::Fndsa1024 as i32 {
            Ok(PublicKey::Fndsa1024(fndsa1024::PublicKey::from_bytes(&key.key)?))
        } else if key.algorithm == schema::public_key::Algorithm::Slhdsa128s as i32 {
            Ok(PublicKey::Slhdsa128s(slhdsa128s::PublicKey::from_bytes(&key.key)?))
        } else if key.algorithm == schema::public_key::Algorithm::Slhdsa128f as i32 {
            Ok(PublicKey::Slhdsa128f(slhdsa128f::PublicKey::from_bytes(&key.key)?))
        } else if key.algorithm == schema::public_key::Algorithm::Slhdsa256s as i32 {
            Ok(PublicKey::Slhdsa256s(slhdsa256s::PublicKey::from_bytes(&key.key)?))
        } else if key.algorithm == schema::public_key::Algorithm::Slhdsa256f as i32 {
            Ok(PublicKey::Slhdsa256f(slhdsa256f::PublicKey::from_bytes(&key.key)?))
        } else if key.algorithm == schema::public_key::Algorithm::HybridEdMldsa44 as i32 {
            Ok(PublicKey::HybridEdMldsa44(hybrid_ed_mldsa44::PublicKey::from_bytes(&key.key)?))
        } else if key.algorithm == schema::public_key::Algorithm::HybridEdFndsa512 as i32 {
            Ok(PublicKey::HybridEdFndsa512(hybrid_ed_fndsa512::PublicKey::from_bytes(&key.key)?))
        } else {
            Err(error::Format::DeserializationError(format!(
                "deserialization error: unexpected key algorithm {}",
                key.algorithm
            )))
        }
    }

    pub fn to_proto(&self) -> schema::PublicKey {
        schema::PublicKey {
            algorithm: self.algorithm() as i32,
            key: self.to_bytes(),
        }
    }

    #[cfg(feature = "pem")]
    pub fn from_der_with_algorithm(
        bytes: &[u8],
        algorithm: Algorithm,
    ) -> Result<Self, error::Format> {
        match algorithm {
            Algorithm::Ed25519 => Ok(PublicKey::Ed25519(ed25519::PublicKey::from_der(bytes)?)),
            Algorithm::Mldsa44 => Ok(PublicKey::Mldsa44(mldsa::PublicKey::from_der(bytes)?)),
            Algorithm::Mldsa65 => Ok(PublicKey::Mldsa65(mldsa65::PublicKey::from_der(bytes)?)),
            Algorithm::Mldsa87 => Ok(PublicKey::Mldsa87(mldsa87::PublicKey::from_der(bytes)?)),
            Algorithm::Fndsa512 => Ok(PublicKey::Fndsa512(fndsa512::PublicKey::from_der(bytes)?)),
            Algorithm::Fndsa1024 => Ok(PublicKey::Fndsa1024(fndsa1024::PublicKey::from_der(bytes)?)),
            Algorithm::Slhdsa128s => Ok(PublicKey::Slhdsa128s(slhdsa128s::PublicKey::from_der(bytes)?)),
            Algorithm::Slhdsa128f => Ok(PublicKey::Slhdsa128f(slhdsa128f::PublicKey::from_der(bytes)?)),
            Algorithm::Slhdsa256s => Ok(PublicKey::Slhdsa256s(slhdsa256s::PublicKey::from_der(bytes)?)),
            Algorithm::Slhdsa256f => Ok(PublicKey::Slhdsa256f(slhdsa256f::PublicKey::from_der(bytes)?)),
            Algorithm::HybridEdMldsa44 => Ok(PublicKey::HybridEdMldsa44(hybrid_ed_mldsa44::PublicKey::from_der(bytes)?)),
            Algorithm::HybridEdFndsa512 => Ok(PublicKey::HybridEdFndsa512(hybrid_ed_fndsa512::PublicKey::from_der(bytes)?)),
            Algorithm::Secp256r1 => Ok(PublicKey::P256(p256::PublicKey::from_der(bytes)?)),
        }
    }

    #[cfg(feature = "pem")]
    pub fn from_der(bytes: &[u8]) -> Result<Self, error::Format> {
        parse_any_algorithm(bytes, Self::from_der_with_algorithm)
    }

    #[cfg(feature = "pem")]
    pub fn from_pem_with_algorithm(str: &str, algorithm: Algorithm) -> Result<Self, error::Format> {
        match algorithm {
            Algorithm::Ed25519 => Ok(PublicKey::Ed25519(ed25519::PublicKey::from_pem(str)?)),
            Algorithm::Mldsa44 => Ok(PublicKey::Mldsa44(mldsa::PublicKey::from_pem(str)?)),
            Algorithm::Mldsa65 => Ok(PublicKey::Mldsa65(mldsa65::PublicKey::from_pem(str)?)),
            Algorithm::Mldsa87 => Ok(PublicKey::Mldsa87(mldsa87::PublicKey::from_pem(str)?)),
            Algorithm::Fndsa512 => Ok(PublicKey::Fndsa512(fndsa512::PublicKey::from_pem(str)?)),
            Algorithm::Fndsa1024 => Ok(PublicKey::Fndsa1024(fndsa1024::PublicKey::from_pem(str)?)),
            Algorithm::Slhdsa128s => Ok(PublicKey::Slhdsa128s(slhdsa128s::PublicKey::from_pem(str)?)),
            Algorithm::Slhdsa128f => Ok(PublicKey::Slhdsa128f(slhdsa128f::PublicKey::from_pem(str)?)),
            Algorithm::Slhdsa256s => Ok(PublicKey::Slhdsa256s(slhdsa256s::PublicKey::from_pem(str)?)),
            Algorithm::Slhdsa256f => Ok(PublicKey::Slhdsa256f(slhdsa256f::PublicKey::from_pem(str)?)),
            Algorithm::HybridEdMldsa44 => Ok(PublicKey::HybridEdMldsa44(hybrid_ed_mldsa44::PublicKey::from_pem(str)?)),
            Algorithm::HybridEdFndsa512 => Ok(PublicKey::HybridEdFndsa512(hybrid_ed_fndsa512::PublicKey::from_pem(str)?)),
            Algorithm::Secp256r1 => Ok(PublicKey::P256(p256::PublicKey::from_pem(str)?)),
        }
    }

    #[cfg(feature = "pem")]
    pub fn from_pem(str: &str) -> Result<Self, error::Format> {
        parse_any_algorithm(str, Self::from_pem_with_algorithm)
    }

    #[cfg(feature = "pem")]
    pub fn to_der(&self) -> Result<Vec<u8>, error::Format> {
        match self {
            PublicKey::Ed25519(key) => key.to_der(),
            PublicKey::Mldsa44(key) => key.to_der(),
            PublicKey::Mldsa65(key) => key.to_der(),
            PublicKey::Mldsa87(key) => key.to_der(),
            PublicKey::Fndsa512(key) => key.to_der(),
            PublicKey::Fndsa1024(key) => key.to_der(),
            PublicKey::Slhdsa128s(key) => key.to_der(),
            PublicKey::Slhdsa128f(key) => key.to_der(),
            PublicKey::Slhdsa256s(key) => key.to_der(),
            PublicKey::Slhdsa256f(key) => key.to_der(),
            PublicKey::HybridEdMldsa44(key) => key.to_der(),
            PublicKey::HybridEdFndsa512(key) => key.to_der(),
            PublicKey::P256(key) => key.to_der(),
        }
    }

    #[cfg(feature = "pem")]
    pub fn to_pem(&self) -> Result<String, error::Format> {
        match self {
            PublicKey::Ed25519(key) => key.to_pem(),
            PublicKey::Mldsa44(key) => key.to_pem(),
            PublicKey::Mldsa65(key) => key.to_pem(),
            PublicKey::Mldsa87(key) => key.to_pem(),
            PublicKey::Fndsa512(key) => key.to_pem(),
            PublicKey::Fndsa1024(key) => key.to_pem(),
            PublicKey::Slhdsa128s(key) => key.to_pem(),
            PublicKey::Slhdsa128f(key) => key.to_pem(),
            PublicKey::Slhdsa256s(key) => key.to_pem(),
            PublicKey::Slhdsa256f(key) => key.to_pem(),
            PublicKey::HybridEdMldsa44(key) => key.to_pem(),
            PublicKey::HybridEdFndsa512(key) => key.to_pem(),
            PublicKey::P256(key) => key.to_pem(),
        }
    }

    pub fn verify_signature(
        &self,
        data: &[u8],
        signature: &Signature,
    ) -> Result<(), error::Format> {
        match self {
            PublicKey::Ed25519(key) => key.verify_signature(data, signature),
            PublicKey::Mldsa44(key) => key.verify_signature(data, signature),
            PublicKey::Mldsa65(key) => key.verify_signature(data, signature),
            PublicKey::Mldsa87(key) => key.verify_signature(data, signature),
            PublicKey::Fndsa512(key) => key.verify_signature(data, signature),
            PublicKey::Fndsa1024(key) => key.verify_signature(data, signature),
            PublicKey::Slhdsa128s(key) => key.verify_signature(data, signature),
            PublicKey::Slhdsa128f(key) => key.verify_signature(data, signature),
            PublicKey::Slhdsa256s(key) => key.verify_signature(data, signature),
            PublicKey::Slhdsa256f(key) => key.verify_signature(data, signature),
            PublicKey::HybridEdMldsa44(key) => key.verify_signature(data, signature),
            PublicKey::HybridEdFndsa512(key) => key.verify_signature(data, signature),
            PublicKey::P256(key) => key.verify_signature(data, signature),
        }
    }

    pub fn algorithm(&self) -> crate::format::schema::public_key::Algorithm {
        match self {
            PublicKey::Ed25519(_) => crate::format::schema::public_key::Algorithm::Ed25519,
            PublicKey::Mldsa44(_) => crate::format::schema::public_key::Algorithm::Mldsa44,
            PublicKey::Mldsa65(_) => crate::format::schema::public_key::Algorithm::Mldsa65,
            PublicKey::Mldsa87(_) => crate::format::schema::public_key::Algorithm::Mldsa87,
            PublicKey::Fndsa512(_) => crate::format::schema::public_key::Algorithm::Fndsa512,
            PublicKey::Fndsa1024(_) => crate::format::schema::public_key::Algorithm::Fndsa1024,
            PublicKey::Slhdsa128s(_) => crate::format::schema::public_key::Algorithm::Slhdsa128s,
            PublicKey::Slhdsa128f(_) => crate::format::schema::public_key::Algorithm::Slhdsa128f,
            PublicKey::Slhdsa256s(_) => crate::format::schema::public_key::Algorithm::Slhdsa256s,
            PublicKey::Slhdsa256f(_) => crate::format::schema::public_key::Algorithm::Slhdsa256f,
            PublicKey::HybridEdMldsa44(_) => crate::format::schema::public_key::Algorithm::HybridEdMldsa44,
            PublicKey::HybridEdFndsa512(_) => crate::format::schema::public_key::Algorithm::HybridEdFndsa512,
            PublicKey::P256(_) => crate::format::schema::public_key::Algorithm::Secp256r1,
        }
    }

    pub fn algorithm_string(&self) -> &str {
        match self {
            PublicKey::Ed25519(_) => "ed25519",
            PublicKey::Mldsa44(_) => "mldsa44",
            PublicKey::Mldsa65(_) => "mldsa65",
            PublicKey::Mldsa87(_) => "mldsa87",
            PublicKey::Fndsa512(_) => "fndsa512",
            PublicKey::Fndsa1024(_) => "fndsa1024",
            PublicKey::Slhdsa128s(_) => "slhdsa128s",
            PublicKey::Slhdsa128f(_) => "slhdsa128f",
            PublicKey::Slhdsa256s(_) => "slhdsa256s",
            PublicKey::Slhdsa256f(_) => "slhdsa256f",
            PublicKey::HybridEdMldsa44(_) => "hybrid-ed-mldsa44",
            PublicKey::HybridEdFndsa512(_) => "hybrid-ed-fndsa512",
            PublicKey::P256(_) => "secp256r1",
        }
    }

    pub(crate) fn write(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PublicKey::Ed25519(key) => key.write(f),
            PublicKey::Mldsa44(key) => key.write(f),
            PublicKey::Mldsa65(key) => key.write(f),
            PublicKey::Mldsa87(key) => key.write(f),
            PublicKey::Fndsa512(key) => key.write(f),
            PublicKey::Fndsa1024(key) => key.write(f),
            PublicKey::Slhdsa128s(key) => key.write(f),
            PublicKey::Slhdsa128f(key) => key.write(f),
            PublicKey::Slhdsa256s(key) => key.write(f),
            PublicKey::Slhdsa256f(key) => key.write(f),
            PublicKey::HybridEdMldsa44(key) => key.write(f),
            PublicKey::HybridEdFndsa512(key) => key.write(f),
            PublicKey::P256(key) => key.write(f),
        }
    }

    pub fn print(&self) -> String {
        match self {
            PublicKey::Ed25519(key) => key.print(),
            PublicKey::Mldsa44(key) => key.print(),
            PublicKey::Mldsa65(key) => key.print(),
            PublicKey::Mldsa87(key) => key.print(),
            PublicKey::Fndsa512(key) => key.print(),
            PublicKey::Fndsa1024(key) => key.print(),
            PublicKey::Slhdsa128s(key) => key.print(),
            PublicKey::Slhdsa128f(key) => key.print(),
            PublicKey::Slhdsa256s(key) => key.print(),
            PublicKey::Slhdsa256f(key) => key.print(),
            PublicKey::HybridEdMldsa44(key) => key.print(),
            PublicKey::HybridEdFndsa512(key) => key.print(),
            PublicKey::P256(key) => key.print(),
        }
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write(f)
    }
}

#[derive(Clone, Debug)]
pub struct Signature(pub(crate) Vec<u8>);

impl Signature {
    pub fn from_bytes(data: &[u8]) -> Result<Self, error::Format> {
        Ok(Signature(data.to_owned()))
    }

    pub(crate) fn from_vec(data: Vec<u8>) -> Self {
        Signature(data)
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

impl FromStr for PublicKey {
    type Err = error::Format;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (_, public_key) = biscuit_parser::parser::public_key(s)
            .finish()
            .map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        PublicKey::from_bytes(
            &public_key.key,
            match public_key.algorithm {
                biscuit_parser::builder::Algorithm::Ed25519 => Algorithm::Ed25519,
                biscuit_parser::builder::Algorithm::Mldsa44 => Algorithm::Mldsa44,
                biscuit_parser::builder::Algorithm::Mldsa65 => Algorithm::Mldsa65,
                biscuit_parser::builder::Algorithm::Mldsa87 => Algorithm::Mldsa87,
                biscuit_parser::builder::Algorithm::Fndsa512 => Algorithm::Fndsa512,
                biscuit_parser::builder::Algorithm::Fndsa1024 => Algorithm::Fndsa1024,
                biscuit_parser::builder::Algorithm::Slhdsa128s => Algorithm::Slhdsa128s,
                biscuit_parser::builder::Algorithm::Slhdsa128f => Algorithm::Slhdsa128f,
                biscuit_parser::builder::Algorithm::Slhdsa256s => Algorithm::Slhdsa256s,
                biscuit_parser::builder::Algorithm::Slhdsa256f => Algorithm::Slhdsa256f,
                biscuit_parser::builder::Algorithm::HybridEdMldsa44 => Algorithm::HybridEdMldsa44,
                biscuit_parser::builder::Algorithm::HybridEdFndsa512 => Algorithm::HybridEdFndsa512,
            biscuit_parser::builder::Algorithm::Secp256r1 => Algorithm::Secp256r1,
            },
        )
    }
}

#[derive(Clone, Debug)]
pub struct Block {
    pub(crate) data: Vec<u8>,
    pub(crate) next_key: PublicKey,
    pub signature: Signature,
    pub external_signature: Option<ExternalSignature>,
    pub version: u32,
}

#[derive(Clone, Debug)]
pub struct ExternalSignature {
    pub(crate) public_key: PublicKey,
    pub(crate) signature: Signature,
}

#[derive(Clone, Debug)]
pub enum TokenNext {
    Secret(PrivateKey),
    Seal(Signature),
}

pub fn sign_authority_block(
    keypair: &KeyPair,
    next_key: &KeyPair,
    message: &[u8],
    version: u32,
) -> Result<Signature, error::Token> {
    let to_sign = match version {
        0 => generate_authority_block_signature_payload_v0(&message, &next_key.public()),
        1 => generate_authority_block_signature_payload_v1(&message, &next_key.public(), version),
        _ => {
            return Err(error::Format::DeserializationError(format!(
                "unsupported block version: {}",
                version
            ))
            .into())
        }
    };

    let signature = keypair.sign(&to_sign)?;

    Ok(Signature(signature.to_bytes().to_vec()))
}

pub fn sign_block(
    keypair: &KeyPair,
    next_key: &KeyPair,
    message: &[u8],
    external_signature: Option<&ExternalSignature>,
    previous_signature: &Signature,
    version: u32,
) -> Result<Signature, error::Token> {
    let to_sign = match version {
        0 => generate_block_signature_payload_v0(&message, &next_key.public(), external_signature),
        1 => generate_block_signature_payload_v1(
            &message,
            &next_key.public(),
            external_signature,
            previous_signature,
            version,
        ),
        _ => {
            return Err(error::Format::DeserializationError(format!(
                "unsupported block version: {}",
                version
            ))
            .into())
        }
    };

    Ok(keypair.sign(&to_sign)?)
}

pub fn verify_authority_block_signature(
    block: &Block,
    public_key: &PublicKey,
) -> Result<(), error::Format> {
    let to_verify = match block.version {
        0 => generate_block_signature_payload_v0(
            &block.data,
            &block.next_key,
            block.external_signature.as_ref(),
        ),
        1 => generate_authority_block_signature_payload_v1(
            &block.data,
            &block.next_key,
            block.version,
        ),
        _ => {
            return Err(error::Format::DeserializationError(format!(
                "unsupported block version: {}",
                block.version
            )))
        }
    };

    public_key.verify_signature(&to_verify, &block.signature)
}

pub fn verify_block_signature(
    block: &Block,
    public_key: &PublicKey,
    previous_signature: &Signature,
    verification_mode: ThirdPartyVerificationMode,
) -> Result<(), error::Format> {
    let to_verify = match block.version {
        0 => generate_block_signature_payload_v0(
            &block.data,
            &block.next_key,
            block.external_signature.as_ref(),
        ),
        1 => generate_block_signature_payload_v1(
            &block.data,
            &block.next_key,
            block.external_signature.as_ref(),
            previous_signature,
            block.version,
        ),
        _ => {
            return Err(error::Format::DeserializationError(format!(
                "unsupported block version: {}",
                block.version
            )))
        }
    };

    public_key.verify_signature(&to_verify, &block.signature)?;

    if let Some(external_signature) = block.external_signature.as_ref() {
        verify_external_signature(
            &block.data,
            public_key,
            previous_signature,
            external_signature,
            block.version,
            verification_mode,
        )?;
    }

    Ok(())
}

pub fn verify_external_signature(
    payload: &[u8],
    public_key: &PublicKey,
    previous_signature: &Signature,
    external_signature: &ExternalSignature,
    version: u32,
    verification_mode: ThirdPartyVerificationMode,
) -> Result<(), error::Format> {
    let to_verify = match verification_mode {
        ThirdPartyVerificationMode::UnsafeLegacy => {
            generate_external_signature_payload_v0(payload, public_key)
        }
        ThirdPartyVerificationMode::PreviousSignatureHashing => {
            generate_external_signature_payload_v1(payload, previous_signature.to_bytes(), version)
        }
    };

    external_signature
        .public_key
        .verify_signature(&to_verify, &external_signature.signature)
}

pub(crate) fn generate_authority_block_signature_payload_v0(
    payload: &[u8],
    next_key: &PublicKey,
) -> Vec<u8> {
    let mut to_verify = payload.to_vec();

    to_verify.extend(&(next_key.algorithm() as i32).to_le_bytes());
    to_verify.extend(next_key.to_bytes());
    to_verify
}

pub(crate) fn generate_block_signature_payload_v0(
    payload: &[u8],
    next_key: &PublicKey,
    external_signature: Option<&ExternalSignature>,
) -> Vec<u8> {
    let mut to_verify = payload.to_vec();

    if let Some(signature) = external_signature.as_ref() {
        to_verify.extend_from_slice(&signature.signature.to_bytes());
    }
    to_verify.extend(&(next_key.algorithm() as i32).to_le_bytes());
    to_verify.extend(next_key.to_bytes());
    to_verify
}

pub(crate) fn generate_authority_block_signature_payload_v1(
    payload: &[u8],
    next_key: &PublicKey,
    version: u32,
) -> Vec<u8> {
    let mut to_verify = b"\0BLOCK\0\0VERSION\0".to_vec();
    to_verify.extend(version.to_le_bytes());

    to_verify.extend(b"\0PAYLOAD\0".to_vec());
    to_verify.extend(payload.to_vec());

    to_verify.extend(b"\0ALGORITHM\0".to_vec());
    to_verify.extend(&(next_key.algorithm() as i32).to_le_bytes());

    to_verify.extend(b"\0NEXTKEY\0".to_vec());
    to_verify.extend(&next_key.to_bytes());

    to_verify
}

pub(crate) fn generate_block_signature_payload_v1(
    payload: &[u8],
    next_key: &PublicKey,
    external_signature: Option<&ExternalSignature>,
    previous_signature: &Signature,
    version: u32,
) -> Vec<u8> {
    let mut to_verify = b"\0BLOCK\0\0VERSION\0".to_vec();
    to_verify.extend(version.to_le_bytes());

    to_verify.extend(b"\0PAYLOAD\0".to_vec());
    to_verify.extend(payload.to_vec());

    to_verify.extend(b"\0ALGORITHM\0".to_vec());
    to_verify.extend(&(next_key.algorithm() as i32).to_le_bytes());

    to_verify.extend(b"\0NEXTKEY\0".to_vec());
    to_verify.extend(&next_key.to_bytes());

    to_verify.extend(b"\0PREVSIG\0".to_vec());
    to_verify.extend(previous_signature.to_bytes());

    if let Some(signature) = external_signature.as_ref() {
        to_verify.extend(b"\0EXTERNALSIG\0".to_vec());
        to_verify.extend_from_slice(&signature.signature.to_bytes());
    }

    to_verify
}

fn generate_external_signature_payload_v0(payload: &[u8], previous_key: &PublicKey) -> Vec<u8> {
    let mut to_verify = payload.to_vec();
    to_verify.extend(&(previous_key.algorithm() as i32).to_le_bytes());
    to_verify.extend(&previous_key.to_bytes());

    to_verify
}

pub(crate) fn generate_external_signature_payload_v1(
    payload: &[u8],
    previous_signature: &[u8],
    version: u32,
) -> Vec<u8> {
    let mut to_verify = b"\0EXTERNAL\0\0VERSION\0".to_vec();
    to_verify.extend(version.to_le_bytes());

    to_verify.extend(b"\0PAYLOAD\0".to_vec());
    to_verify.extend(payload.to_vec());

    to_verify.extend(b"\0PREVSIG\0".to_vec());
    to_verify.extend(previous_signature);
    to_verify
}

pub(crate) fn generate_seal_signature_payload_v0(block: &Block) -> Vec<u8> {
    let mut to_verify = block.data.to_vec();
    to_verify.extend(&(block.next_key.algorithm() as i32).to_le_bytes());
    to_verify.extend(&block.next_key.to_bytes());
    to_verify.extend(block.signature.to_bytes());
    to_verify
}

impl TokenNext {
    pub fn keypair(&self) -> Result<KeyPair, error::Token> {
        match &self {
            TokenNext::Seal(_) => Err(error::Token::AlreadySealed),
            TokenNext::Secret(private) => Ok(KeyPair::from(private)),
        }
    }

    pub fn is_sealed(&self) -> bool {
        match &self {
            TokenNext::Seal(_) => true,
            TokenNext::Secret(_) => false,
        }
    }
}

fn parse_any_algorithm<I: Copy, O>(
    i: I,
    parse: fn(i: I, alg: Algorithm) -> Result<O, error::Format>,
) -> Result<O, error::Format> {
    for algorithm in Algorithm::values() {
        let res = parse(i, *algorithm);
        if res.is_ok() {
            return res;
        }
    }

    Err(error::Format::InvalidKey(
        "The key could not be parsed with any algorithm".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_from_string() {
        let ed_root = KeyPair::new_with_algorithm(Algorithm::Ed25519);
        assert_eq!(
            ed_root.public(),
            ed_root.public().to_string().parse().unwrap()
        );
        assert_eq!(
            ed_root.private().to_bytes(),
            ed_root
                .private()
                .to_prefixed_string()
                .parse::<PrivateKey>()
                .unwrap()
                .to_bytes()
        );
        let p256_root = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
        assert_eq!(
            p256_root.public(),
            p256_root.public().to_string().parse().unwrap()
        );
        assert_eq!(
            p256_root.private().to_bytes(),
            p256_root
                .private()
                .to_prefixed_string()
                .parse::<PrivateKey>()
                .unwrap()
                .to_bytes()
        )
    }

    #[test]
    fn parsing_ed25519() {
        let private_ed = PrivateKey::from_bytes_hex(
            "bf6065d753c4a2c679dcd28828ac625c6c713efee2d4dd4b9c9ff3c9a2b2f966",
            Algorithm::Ed25519,
        )
        .unwrap();

        assert_eq!(
            private_ed.to_prefixed_string(),
            "ed25519-private/bf6065d753c4a2c679dcd28828ac625c6c713efee2d4dd4b9c9ff3c9a2b2f966"
                .to_string()
        );

        let public_ed = PublicKey::from_bytes_hex(
            "eb396fa7a681c614fefc5bd8d1fa0383f30a8c562a99d8e8a830286e844be074",
            Algorithm::Ed25519,
        )
        .unwrap();

        assert_eq!(
            public_ed.to_string(),
            "ed25519/eb396fa7a681c614fefc5bd8d1fa0383f30a8c562a99d8e8a830286e844be074".to_string()
        );
    }

    #[test]
    fn parsing_secp256r1() {
        let private_p256 = PrivateKey::from_bytes_hex(
            "4e85237ab258ca7d53051073dd6c1e501ea4699f2fed6b0f5d399dc2a5f7d38f",
            Algorithm::Secp256r1,
        )
        .unwrap();

        assert_eq!(
            private_p256.to_prefixed_string(),
            "secp256r1-private/4e85237ab258ca7d53051073dd6c1e501ea4699f2fed6b0f5d399dc2a5f7d38f"
                .to_string()
        );

        let public_p256 = PublicKey::from_bytes_hex(
            "03b6d94743381d3452f11a1aec8d73b0a899827d48be2e4387112e4d2faacfcc29",
            Algorithm::Secp256r1,
        )
        .unwrap();

        assert_eq!(
            public_p256.to_string(),
            "secp256r1/03b6d94743381d3452f11a1aec8d73b0a899827d48be2e4387112e4d2faacfcc29"
                .to_string()
        );

        assert_eq!(
            public_p256,
            "secp256r1/03b6d94743381d3452f11a1aec8d73b0a899827d48be2e4387112e4d2faacfcc29"
                .parse()
                .unwrap()
        );
    }
    #[test]
    fn parsing_errors() {
        "xx/03b6d94743381d3452f11a1aec8d73b0a899827d48be2e4387112e4d2faacfcc29"
            .parse::<PublicKey>()
            .unwrap_err();
        "03b6d94743381d3452f11a1aec8d73b0a899827d48be2e4387112e4d2faacfcc29"
            .parse::<PublicKey>()
            .unwrap_err();

        "xx/03b6d94743381d3452f11a1aec8d73b0a899827d48be2e4387112e4d2faacfcc29"
            .parse::<PrivateKey>()
            .unwrap_err();
        "03b6d94743381d3452f11a1aec8d73b0a899827d48be2e4387112e4d2faacfcc29"
            .parse::<PrivateKey>()
            .unwrap_err();
    }

    #[cfg(feature = "pem")]
    #[test]
    fn ed25519_der() {
        let ed25519_kp = KeyPair::new_with_algorithm(Algorithm::Ed25519);
        let der_kp = ed25519_kp.to_private_key_der().unwrap();

        let deser =
            KeyPair::from_private_key_der_with_algorithm(&der_kp, Algorithm::Ed25519).unwrap();
        assert_eq!(ed25519_kp, deser);
        let deser = KeyPair::from_private_key_der(&der_kp).unwrap();
        assert_eq!(ed25519_kp, deser);

        let ed25519_priv = ed25519_kp.private();
        let der_priv = ed25519_priv.to_der().unwrap();
        let deser_priv =
            PrivateKey::from_der_with_algorithm(&der_priv, Algorithm::Ed25519).unwrap();
        assert_eq!(ed25519_priv, deser_priv);
        let deser_priv = PrivateKey::from_der(&der_priv).unwrap();
        assert_eq!(ed25519_priv, deser_priv);

        let ed25519_pub = ed25519_kp.public();
        let der_pub = ed25519_pub.to_der().unwrap();
        let deser_pub = PublicKey::from_der_with_algorithm(&der_pub, Algorithm::Ed25519).unwrap();
        assert_eq!(ed25519_pub, deser_pub);
        let deser_pub = PublicKey::from_der(&der_pub).unwrap();
        assert_eq!(ed25519_pub, deser_pub);
    }

    #[cfg(feature = "pem")]
    #[test]
    fn ed25519_pem() {
        let ed25519_kp = KeyPair::new_with_algorithm(Algorithm::Ed25519);
        let pem_kp = ed25519_kp.to_private_key_pem().unwrap();
        let deser =
            KeyPair::from_private_key_pem_with_algorithm(&pem_kp, Algorithm::Ed25519).unwrap();
        assert_eq!(ed25519_kp, deser);
        let deser = KeyPair::from_private_key_pem(&pem_kp).unwrap();
        assert_eq!(ed25519_kp, deser);

        let ed25519_priv = ed25519_kp.private();
        let pem_priv = ed25519_priv.to_pem().unwrap();
        let deser_priv =
            PrivateKey::from_pem_with_algorithm(&pem_priv, Algorithm::Ed25519).unwrap();
        assert_eq!(ed25519_priv, deser_priv);
        let deser_priv = PrivateKey::from_pem(&pem_priv).unwrap();
        assert_eq!(ed25519_priv, deser_priv);

        let ed25519_pub = ed25519_kp.public();
        let pem_pub = ed25519_pub.to_pem().unwrap();
        let deser_pub = PublicKey::from_pem_with_algorithm(&pem_pub, Algorithm::Ed25519).unwrap();
        assert_eq!(ed25519_pub, deser_pub);
        let deser_pub = PublicKey::from_pem(&pem_pub).unwrap();
        assert_eq!(ed25519_pub, deser_pub);
    }

    #[cfg(feature = "pem")]
    #[test]
    fn p256_der() {
        let p256_kp = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
        let der_kp = p256_kp.to_private_key_der().unwrap();
        let deser =
            KeyPair::from_private_key_der_with_algorithm(&der_kp, Algorithm::Secp256r1).unwrap();
        assert_eq!(p256_kp, deser);
        let deser = KeyPair::from_private_key_der(&der_kp).unwrap();
        assert_eq!(p256_kp, deser);

        let p256_priv = p256_kp.private();
        let der_priv = p256_priv.to_der().unwrap();
        let deser_priv =
            PrivateKey::from_der_with_algorithm(&der_priv, Algorithm::Secp256r1).unwrap();
        assert_eq!(p256_priv, deser_priv);
        let deser_priv = PrivateKey::from_der(&der_priv).unwrap();
        assert_eq!(p256_priv, deser_priv);

        let p256_pub = p256_kp.public();
        let der_pub = p256_pub.to_der().unwrap();
        let deser_pub = PublicKey::from_der_with_algorithm(&der_pub, Algorithm::Secp256r1).unwrap();
        assert_eq!(p256_pub, deser_pub);
        let deser_pub = PublicKey::from_der(&der_pub).unwrap();
        assert_eq!(p256_pub, deser_pub);
    }

    #[cfg(feature = "pem")]
    #[test]
    fn p256_pem() {
        let p256_kp = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
        let pem_kp = p256_kp.to_private_key_pem().unwrap();
        let deser =
            KeyPair::from_private_key_pem_with_algorithm(&pem_kp, Algorithm::Secp256r1).unwrap();
        assert_eq!(p256_kp, deser);
        let deser = KeyPair::from_private_key_pem(&pem_kp).unwrap();
        assert_eq!(p256_kp, deser);

        let p256_priv = p256_kp.private();
        let pem_priv = p256_priv.to_pem().unwrap();
        let deser_priv =
            PrivateKey::from_pem_with_algorithm(&pem_priv, Algorithm::Secp256r1).unwrap();
        assert_eq!(p256_priv, deser_priv);
        let deser_priv = PrivateKey::from_pem(&pem_priv).unwrap();
        assert_eq!(p256_priv, deser_priv);

        let p256_pub = p256_kp.public();
        let pem_pub = p256_pub.to_pem().unwrap();
        let deser_pub = PublicKey::from_pem_with_algorithm(&pem_pub, Algorithm::Secp256r1).unwrap();
        assert_eq!(p256_pub, deser_pub);
        let deser_pub = PublicKey::from_pem(&pem_pub).unwrap();
        assert_eq!(p256_pub, deser_pub);
    }
}
