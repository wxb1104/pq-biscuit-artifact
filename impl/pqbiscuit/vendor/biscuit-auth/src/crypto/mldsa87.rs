//! ML-DSA-87 post-quantum backend, generated via `pq_backend!`.
//!
//! Identical logic to the hand-written ML-DSA-44 backend in
//! `mldsa.rs`; only the PQClean parameter set and key lengths differ.
use crate::pq_backend;

pq_backend!(pqcrypto_dilithium::dilithium5, 2592, 4896, "mldsa87", "ML-DSA-87");
