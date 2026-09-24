//! E-N offline token/root-key generator for the network testbed.
//!
//! For every chain profile and attenuation length n, mints a sealed Biscuit
//! offline and writes:
//!   * rootkeys/<profile>.pub    : root public key (PublicKey Display form),
//!                                 provisioned to the server out of band;
//!   * tokens/<profile>_n<n>.tok : base64url(sealed token), held by the client;
//!   * net_tokens_manifest.csv   : profile,family,root,att,n,raw_b,b64_b.
//!
//! One root key is minted per profile and reused across n (one issuer minting
//! chains of different lengths). Signing/key generation is offline and is
//! deliberately excluded from network latency; its cost is quantified by the
//! E5/E55/E6 micro-benchmarks.
//!
//! Run (from impl/pqbiscuit): `cargo run --release --bin netbed_gen`.

#[path = "netbed/common.rs"]
mod common;
use biscuit_auth::KeyPair;
use common::*;
use std::error::Error;
use std::fs;
use std::time::Instant;

fn main() -> Result<(), Box<dyn Error>> {
    ensure_dirs();
    let mut manifest = String::from("profile,family,root,att,n,raw_b,b64_b\n");

    for profile in profiles() {
        let att_s = profile.att.unwrap_or(profile.root);
        let t_all = Instant::now();
        let root = KeyPair::new_with_algorithm(parse_alg(profile.root));
        fs::write(root_key_path(profile.name), root.public().to_string())?;

        for &n in NS.iter() {
            let sealed = seal_token(build_chain(&root, profile, n));
            let b64 = b64url_encode(&sealed);
            fs::write(token_path(profile.name, n), &b64)?;
            manifest.push_str(&format!(
                "{},{},{},{},{},{},{}\n",
                profile.name, profile.family, profile.root, att_s, n,
                sealed.len(), b64.len()
            ));
        }
        println!("[{:>22}] root + {} lengths done in {:.2?}",
                 profile.name, NS.len(), t_all.elapsed());
    }

    fs::write(format!("{OUT_DIR}/net_tokens_manifest.csv"), manifest)?;
    println!("wrote {OUT_DIR}/net_tokens_manifest.csv, rootkeys/, tokens/");
    Ok(())
}
