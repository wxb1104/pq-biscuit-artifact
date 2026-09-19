//! SLH-DSA-256f post-quantum backend, generated via `pq_backend!`.
//!
//! Identical logic to the hand-written ML-DSA-44 backend in
//! `mldsa.rs`; only the PQClean parameter set and key lengths differ.
use crate::pq_backend;

pq_backend!(pqcrypto_sphincsplus::sphincssha2256fsimple, 64, 128, "slhdsa256f", "SLH-DSA-256f");
