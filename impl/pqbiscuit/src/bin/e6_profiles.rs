//! E6-C deployment profiles: end-to-end sealed size and chain-verification latency.
//!
//! Compares concrete migration strategies over attenuation depth n in {0,1,2,5,10,20}:
//!   all-ed                 : classical Ed25519 baseline
//!   all-mldsa44            : uniform ML-DSA-44
//!   all-fndsa512           : uniform FN-DSA-512
//!   hybrid-ed-mldsa44      : uniform hybrid Ed25519+ML-DSA-44
//!   hybrid-ed-fndsa512     : uniform hybrid Ed25519+FN-DSA-512
//!   mixed-mldsa87-root-fn  : strong ML-DSA-87 root (signed once offline), FN-512 hops
//!   mixed-slh128s-root-fn  : conservative hash-only SLH-128s root, FN-512 hops
//!
//! Size is deterministic (one sample); verification (Biscuit::from = full signature
//! chain check) is timed with 51 reps (10 warm-up), pinned to one core externally.
//!
//! Outputs: e6_profiles_size.csv (profile,n,size_bytes)
//!          e6_profiles_verify.csv (profile,n,rep,ns)

use std::error::Error;
use std::fs;
use std::hint::black_box;
use std::time::Instant;

use biscuit_auth::{Algorithm, Biscuit, BlockBuilder, KeyPair};

fn atten() -> BlockBuilder {
    BlockBuilder::new().check("check if operation(\"read\")").unwrap()
}

fn build_profile(root_alg: Algorithm, hop_alg: Algorithm, n: usize) -> (KeyPair, Vec<u8>) {
    let root = KeyPair::new_with_algorithm(root_alg);
    let mut t = Biscuit::builder().fact("right(\"file1\", \"read\")").unwrap().build(&root).unwrap();
    for _ in 0..n {
        t = t.append_with_keypair(&KeyPair::new_with_algorithm(hop_alg), atten()).unwrap();
    }
    let bytes = t.seal().unwrap().to_vec().unwrap();
    (root, bytes)
}

fn main() -> Result<(), Box<dyn Error>> {
    let profiles: &[(&str, Algorithm, Algorithm)] = &[
        ("all-ed",                Algorithm::Ed25519,      Algorithm::Ed25519),
        ("all-mldsa44",           Algorithm::Mldsa44,      Algorithm::Mldsa44),
        ("all-fndsa512",          Algorithm::Fndsa512,     Algorithm::Fndsa512),
        ("hybrid-ed-mldsa44",     Algorithm::HybridEdMldsa44, Algorithm::HybridEdMldsa44),
        ("hybrid-ed-fndsa512",    Algorithm::HybridEdFndsa512, Algorithm::HybridEdFndsa512),
        ("mixed-mldsa87-root-fn", Algorithm::Mldsa87,      Algorithm::Fndsa512),
        ("mixed-slh128s-root-fn", Algorithm::Slhdsa128s,   Algorithm::Fndsa512),
    ];
    let ns = [0usize, 1, 2, 5, 10, 20];
    let reps = 51u32;
    let warm = 10u32;

    let mut size_out = String::from("profile,n,size_bytes\n");
    let mut ver_out = String::from("profile,n,rep,ns\n");

    for (name, root_alg, hop_alg) in profiles {
        for &n in &ns {
            let (root, bytes) = build_profile(*root_alg, *hop_alg, n);
            size_out.push_str(&format!("{name},{n},{}\n", bytes.len()));
            let pk = root.public();
            for r in 0..(reps + warm) {
                let b = bytes.clone();
                let t0 = Instant::now();
                let tok = Biscuit::from(&b, pk).unwrap();
                black_box(&tok);
                let ns_el = t0.elapsed().as_nanos();
                if r >= warm {
                    ver_out.push_str(&format!("{name},{n},{},{ns_el}\n", r - warm));
                }
            }
        }
        println!("[{name:>22}] done");
    }

    let outdir = "../../experiments/data";
    fs::create_dir_all(outdir)?;
    fs::write(format!("{outdir}/e6_profiles_size.csv"), size_out)?;
    fs::write(format!("{outdir}/e6_profiles_verify.csv"), ver_out)?;
    println!("wrote e6_profiles_size.csv and e6_profiles_verify.csv");
    Ok(())
}
