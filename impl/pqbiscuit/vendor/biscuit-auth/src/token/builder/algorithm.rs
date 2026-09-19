/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
use core::fmt::Display;
use std::{
    convert::{TryFrom, TryInto},
    str::FromStr,
};

use crate::error;

#[derive(Debug, Copy, Clone, PartialEq, Hash, Eq)]
pub enum Algorithm {
    Ed25519,
    Mldsa44,
    Mldsa65,
    Mldsa87,
    Fndsa512,
    Fndsa1024,
    Slhdsa128s,
    Slhdsa128f,
    Slhdsa256s,
    Slhdsa256f,
    HybridEdMldsa44,
    HybridEdFndsa512,
    Secp256r1,
}

impl Algorithm {
    pub fn values() -> &'static [Self] {
        &[Self::Ed25519, Self::Mldsa44, Self::Mldsa65, Self::Mldsa87, Self::Fndsa512, Self::Fndsa1024, Self::Slhdsa128s, Self::Slhdsa128f, Self::Slhdsa256s, Self::Slhdsa256f, Self::HybridEdMldsa44, Self::HybridEdFndsa512, Self::Secp256r1]
    }
}

impl Default for Algorithm {
    fn default() -> Self {
        Self::Ed25519
    }
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::Ed25519 => write!(f, "ed25519"),
            Algorithm::Mldsa44 => write!(f, "mldsa44"),
            Algorithm::Mldsa65 => write!(f, "mldsa65"),
            Algorithm::Mldsa87 => write!(f, "mldsa87"),
            Algorithm::Fndsa512 => write!(f, "fndsa512"),
            Algorithm::Fndsa1024 => write!(f, "fndsa1024"),
            Algorithm::Slhdsa128s => write!(f, "slhdsa128s"),
            Algorithm::Slhdsa128f => write!(f, "slhdsa128f"),
            Algorithm::Slhdsa256s => write!(f, "slhdsa256s"),
            Algorithm::Slhdsa256f => write!(f, "slhdsa256f"),
            Algorithm::HybridEdMldsa44 => write!(f, "hybrid-ed-mldsa44"),
            Algorithm::HybridEdFndsa512 => write!(f, "hybrid-ed-fndsa512"),
            Algorithm::Secp256r1 => write!(f, "secp256r1"),
        }
    }
}
impl FromStr for Algorithm {
    type Err = error::Format;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl TryFrom<&str> for Algorithm {
    type Error = error::Format;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "ed25519" => Ok(Algorithm::Ed25519),
            "mldsa44" => Ok(Algorithm::Mldsa44),
            "mldsa65" => Ok(Algorithm::Mldsa65),
            "mldsa87" => Ok(Algorithm::Mldsa87),
            "fndsa512" => Ok(Algorithm::Fndsa512),
            "fndsa1024" => Ok(Algorithm::Fndsa1024),
            "slhdsa128s" => Ok(Algorithm::Slhdsa128s),
            "slhdsa128f" => Ok(Algorithm::Slhdsa128f),
            "slhdsa256s" => Ok(Algorithm::Slhdsa256s),
            "slhdsa256f" => Ok(Algorithm::Slhdsa256f),
            "hybrid-ed-mldsa44" => Ok(Algorithm::HybridEdMldsa44),
            "hybrid-ed-fndsa512" => Ok(Algorithm::HybridEdFndsa512),
            "secp256r1" => Ok(Algorithm::Secp256r1),
            _ => Err(error::Format::DeserializationError(format!(
                "deserialization error: unexpected key algorithm {}",
                value
            ))),
        }
    }
}

impl From<biscuit_parser::builder::Algorithm> for Algorithm {
    fn from(value: biscuit_parser::builder::Algorithm) -> Algorithm {
        match value {
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
        }
    }
}

impl From<Algorithm> for biscuit_parser::builder::Algorithm {
    fn from(value: Algorithm) -> biscuit_parser::builder::Algorithm {
        match value {
            Algorithm::Ed25519 => biscuit_parser::builder::Algorithm::Ed25519,
            Algorithm::Mldsa44 => biscuit_parser::builder::Algorithm::Mldsa44,
            Algorithm::Mldsa65 => biscuit_parser::builder::Algorithm::Mldsa65,
            Algorithm::Mldsa87 => biscuit_parser::builder::Algorithm::Mldsa87,
            Algorithm::Fndsa512 => biscuit_parser::builder::Algorithm::Fndsa512,
            Algorithm::Fndsa1024 => biscuit_parser::builder::Algorithm::Fndsa1024,
            Algorithm::Slhdsa128s => biscuit_parser::builder::Algorithm::Slhdsa128s,
            Algorithm::Slhdsa128f => biscuit_parser::builder::Algorithm::Slhdsa128f,
            Algorithm::Slhdsa256s => biscuit_parser::builder::Algorithm::Slhdsa256s,
            Algorithm::Slhdsa256f => biscuit_parser::builder::Algorithm::Slhdsa256f,
            Algorithm::HybridEdMldsa44 => biscuit_parser::builder::Algorithm::HybridEdMldsa44,
            Algorithm::HybridEdFndsa512 => biscuit_parser::builder::Algorithm::HybridEdFndsa512,
            Algorithm::Secp256r1 => biscuit_parser::builder::Algorithm::Secp256r1,
        }
    }
}

impl From<crate::format::schema::public_key::Algorithm> for Algorithm {
    fn from(value: crate::format::schema::public_key::Algorithm) -> Algorithm {
        match value {
            crate::format::schema::public_key::Algorithm::Ed25519 => Algorithm::Ed25519,
            crate::format::schema::public_key::Algorithm::Mldsa44 => Algorithm::Mldsa44,
            crate::format::schema::public_key::Algorithm::Mldsa65 => Algorithm::Mldsa65,
            crate::format::schema::public_key::Algorithm::Mldsa87 => Algorithm::Mldsa87,
            crate::format::schema::public_key::Algorithm::Fndsa512 => Algorithm::Fndsa512,
            crate::format::schema::public_key::Algorithm::Fndsa1024 => Algorithm::Fndsa1024,
            crate::format::schema::public_key::Algorithm::Slhdsa128s => Algorithm::Slhdsa128s,
            crate::format::schema::public_key::Algorithm::Slhdsa128f => Algorithm::Slhdsa128f,
            crate::format::schema::public_key::Algorithm::Slhdsa256s => Algorithm::Slhdsa256s,
            crate::format::schema::public_key::Algorithm::Slhdsa256f => Algorithm::Slhdsa256f,
            crate::format::schema::public_key::Algorithm::HybridEdMldsa44 => Algorithm::HybridEdMldsa44,
            crate::format::schema::public_key::Algorithm::HybridEdFndsa512 => Algorithm::HybridEdFndsa512,
            crate::format::schema::public_key::Algorithm::Secp256r1 => Algorithm::Secp256r1,
        }
    }
}

impl From<Algorithm> for crate::format::schema::public_key::Algorithm {
    fn from(value: Algorithm) -> crate::format::schema::public_key::Algorithm {
        match value {
            Algorithm::Ed25519 => crate::format::schema::public_key::Algorithm::Ed25519,
            Algorithm::Mldsa44 => crate::format::schema::public_key::Algorithm::Mldsa44,
            Algorithm::Mldsa65 => crate::format::schema::public_key::Algorithm::Mldsa65,
            Algorithm::Mldsa87 => crate::format::schema::public_key::Algorithm::Mldsa87,
            Algorithm::Fndsa512 => crate::format::schema::public_key::Algorithm::Fndsa512,
            Algorithm::Fndsa1024 => crate::format::schema::public_key::Algorithm::Fndsa1024,
            Algorithm::Slhdsa128s => crate::format::schema::public_key::Algorithm::Slhdsa128s,
            Algorithm::Slhdsa128f => crate::format::schema::public_key::Algorithm::Slhdsa128f,
            Algorithm::Slhdsa256s => crate::format::schema::public_key::Algorithm::Slhdsa256s,
            Algorithm::Slhdsa256f => crate::format::schema::public_key::Algorithm::Slhdsa256f,
            Algorithm::HybridEdMldsa44 => crate::format::schema::public_key::Algorithm::HybridEdMldsa44,
            Algorithm::HybridEdFndsa512 => crate::format::schema::public_key::Algorithm::HybridEdFndsa512,
            Algorithm::Secp256r1 => crate::format::schema::public_key::Algorithm::Secp256r1,
        }
    }
}
