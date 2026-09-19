//! FN-DSA-512 post-quantum backend, generated via `pq_backend!`.
//!
//! Identical logic to the hand-written ML-DSA-44 backend in
//! `mldsa.rs`; only the PQClean parameter set and key lengths differ.
use crate::pq_backend;

pq_backend!(pqcrypto_falcon::falcon512, 897, 1281, "fndsa512", "FN-DSA-512");
