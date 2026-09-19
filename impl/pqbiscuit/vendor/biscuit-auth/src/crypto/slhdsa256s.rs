//! SLH-DSA-256s post-quantum backend, generated via `pq_backend!`.
//!
//! Identical logic to the hand-written ML-DSA-44 backend in
//! `mldsa.rs`; only the PQClean parameter set and key lengths differ.
use crate::pq_backend;

pq_backend!(pqcrypto_sphincsplus::sphincssha2256ssimple, 64, 128, "slhdsa256s", "SLH-DSA-256s");
