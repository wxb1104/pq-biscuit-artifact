//! Labelled strong-nesting hybrid backend: inner Ed25519 (classical) +
//! outer FN-DSA-512 / Falcon-512 (post-quantum). Construction H(Σ1,Σ2) per
//! OpenSK/Bindel; see `crypto/hybridmacro.rs` and
//! `sources/excerpts/hybrid_combiner_excerpt.md`.
use crate::hybrid_backend;

hybrid_backend!(
    fndsa512,
    897,
    1281,
    "hybrid-ed-fndsa512",
    "Hybrid Ed25519 + FN-DSA-512",
    "biscuit-hybrid-v1|inner=ed25519|outer=fndsa512"
);
