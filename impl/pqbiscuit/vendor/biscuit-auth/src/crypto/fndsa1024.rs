//! FN-DSA-1024 post-quantum backend, generated via `pq_backend!`.
//!
//! Identical logic to the hand-written ML-DSA-44 backend in
//! `mldsa.rs`; only the PQClean parameter set and key lengths differ.
use crate::pq_backend;

pq_backend!(pqcrypto_falcon::falcon1024, 1793, 2305, "fndsa1024", "FN-DSA-1024");
