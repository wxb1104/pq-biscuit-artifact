//! E5-5 hybrid combiner real-system benchmark.
//!
//! Benchmarks the two labelled strong-nesting hybrids against their component
//! baselines (Ed25519, ML-DSA-44, FN-DSA-512):
//!   * size sweep n = 0..=20 (e55_hybrid_size.csv);
//!   * five-phase latency, 101 reps over n in {0,1,2,5,10,20}
//!     (e55_hybrid_latency.csv).
//!
//! Run: `cargo run --release --bin e55_hybrid_bench`.

use std::error::Error;
use std::fs;
use std::hint::black_box;
use std::time::Instant;

use biscuit_auth::builder_ext::AuthorizerExt;
use biscuit_auth::{Algorithm, AuthorizerBuilder, Biscuit, BlockBuilder, KeyPair};

const MAX_N: usize = 20;
const NS: [usize; 6] = [0, 1, 2, 5, 10, 20];
const REPS: usize = 101;
const WARMUP: usize = 10;

fn atten_block() -> BlockBuilder {
    BlockBuilder::new()
        .check("check if operation(\"read\")")
        .expect("valid attenuation check")
}

fn make_token(root: &KeyPair, alg: Algorithm, n: usize) -> Biscuit {
    let mut token = Biscuit::builder()
        .fact("right(\"file1\", \"read\")")
        .unwrap()
        .fact("right(\"file1\", \"write\")")
        .unwrap()
        .build(root)
        .expect("authority build");
    for _ in 0..n {
        let kp = KeyPair::new_with_algorithm(alg);
        token = token.append_with_keypair(&kp, atten_block()).expect("append");
    }
    token
}

fn median_ns<R>(reps: usize, warmup: usize, mut f: impl FnMut() -> R) -> u128 {
    for _ in 0..warmup {
        black_box(f());
    }
    let mut samples = Vec::with_capacity(reps);
    for _ in 0..reps {
        let start = Instant::now();
        let r = f();
        black_box(r);
        samples.push(start.elapsed().as_nanos());
    }
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn run(alg: Algorithm, size_rows: &mut String, lat_rows: &mut String) {
    let name = format!("{alg:?}");
    let root = KeyPair::new_with_algorithm(alg);

    for n in 0..=MAX_N {
        let token = make_token(&root, alg, n);
        let unsealed = token.to_vec().expect("unsealed serialize");
        let sealed = token.seal().expect("seal").to_vec().expect("sealed serialize");
        size_rows.push_str(&format!("{name},{n},{},{}\n", unsealed.len(), sealed.len()));
    }

    for &n in &NS {
        let t_auth = median_ns(REPS, WARMUP, || {
            Biscuit::builder()
                .fact("right(\"file1\", \"read\")")
                .unwrap()
                .fact("right(\"file1\", \"write\")")
                .unwrap()
                .build(&root)
                .unwrap()
        });
        lat_rows.push_str(&format!("{name},{n},authority_build,{t_auth},{REPS}\n"));

        let base = make_token(&root, alg, n);
        let t_append = median_ns(REPS, WARMUP, || {
            let kp = KeyPair::new_with_algorithm(alg);
            base.append_with_keypair(&kp, atten_block()).unwrap()
        });
        lat_rows.push_str(&format!("{name},{n},append_hop,{t_append},{REPS}\n"));

        let unsealed = make_token(&root, alg, n);
        let t_seal = median_ns(REPS, WARMUP, || unsealed.seal().unwrap());
        lat_rows.push_str(&format!("{name},{n},seal,{t_seal},{REPS}\n"));

        let sealed_bytes = make_token(&root, alg, n)
            .seal()
            .unwrap()
            .to_vec()
            .unwrap();
        let t_verify = median_ns(REPS, WARMUP, || {
            Biscuit::from(&sealed_bytes, root.public()).unwrap()
        });
        lat_rows.push_str(&format!("{name},{n},verify_chain,{t_verify},{REPS}\n"));

        let parsed = Biscuit::from(&sealed_bytes, root.public()).unwrap();
        let t_authz = median_ns(REPS, WARMUP, || {
            AuthorizerBuilder::new()
                .fact("resource(\"file1\")")
                .unwrap()
                .fact("operation(\"read\")")
                .unwrap()
                .allow_all()
                .build(&parsed)
                .unwrap()
                .authorize()
                .unwrap()
        });
        lat_rows.push_str(&format!("{name},{n},authorize,{t_authz},{REPS}\n"));
    }
    println!("[{name:>17}] size 0..={MAX_N}, latency {REPS} reps x {} n-values done", NS.len());
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut size_rows = String::from("alg,n,unsealed_bytes,sealed_bytes\n");
    let mut lat_rows = String::from("alg,n,phase,median_ns,reps\n");

    for alg in [
        Algorithm::Ed25519,
        Algorithm::Mldsa44,
        Algorithm::Fndsa512,
        Algorithm::HybridEdMldsa44,
        Algorithm::HybridEdFndsa512,
    ] {
        run(alg, &mut size_rows, &mut lat_rows);
    }

    let out = "../../experiments/data";
    fs::create_dir_all(out)?;
    fs::write(format!("{out}/e55_hybrid_size.csv"), size_rows)?;
    fs::write(format!("{out}/e55_hybrid_latency.csv"), lat_rows)?;
    println!("wrote {out}/e55_hybrid_size.csv and e55_hybrid_latency.csv");
    Ok(())
}
