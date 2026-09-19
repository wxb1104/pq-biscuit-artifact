//! ML-DSA-65 post-quantum backend, generated via `pq_backend!`.
//!
//! Identical logic to the hand-written ML-DSA-44 backend in
//! `mldsa.rs`; only the PQClean parameter set and key lengths differ.
use crate::pq_backend;

pq_backend!(pqcrypto_dilithium::dilithium3, 1952, 4032, "mldsa65", "ML-DSA-65");
