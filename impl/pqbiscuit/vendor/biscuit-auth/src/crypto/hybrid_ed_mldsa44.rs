//! Labelled strong-nesting hybrid backend: inner Ed25519 (classical) +
//! outer ML-DSA-44 (post-quantum). Construction H(Σ1,Σ2) per OpenSK/Bindel;
//! see `crypto/hybridmacro.rs` and `sources/excerpts/hybrid_combiner_excerpt.md`.
use crate::hybrid_backend;

hybrid_backend!(
    mldsa,
    1312,
    2560,
    "hybrid-ed-mldsa44",
    "Hybrid Ed25519 + ML-DSA-44",
    "biscuit-hybrid-v1|inner=ed25519|outer=mldsa44"
);
