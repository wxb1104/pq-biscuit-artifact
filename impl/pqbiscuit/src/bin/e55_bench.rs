//! E5-5 full-algorithm real-system benchmark.
//!
//! Extends e5bench to all nine post-quantum parameter sets plus Ed25519:
//!   * size sweep n = 0..=20 for every algorithm (writes e55_token_size.csv);
//!   * five-phase latency, 101 reps for fast schemes (Ed/ML-DSA/FN-DSA) and a
//!     reduced 5 reps over small n for the deliberately slow stateless
//!     hash-based SLH-DSA schemes (writes e55_latency.csv).
//!
//! Run: `cargo run --release --bin e55_bench`.

use std::error::Error;
use std::fs;
use std::hint::black_box;
use std::time::Instant;

use biscuit_auth::builder_ext::AuthorizerExt;
use biscuit_auth::{Algorithm, AuthorizerBuilder, Biscuit, BlockBuilder, KeyPair};

const MAX_N: usize = 20;
const FAST_NS: [usize; 6] = [0, 1, 2, 5, 10, 20];
const SLOW_NS: [usize; 3] = [0, 1, 2];
const FAST_REPS: usize = 101;
const SLOW_REPS: usize = 5;

fn atten_block() -> BlockBuilder {
    BlockBuilder::new()
        .check("check if operation(\"read\")")
        .expect("valid attenuation check")
}

/// authority block (two rights) + n fresh-key attenuation blocks
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
        token = token
            .append_with_keypair(&kp, atten_block())
            .expect("append");
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

fn run(alg: Algorithm, reps: usize, warmup: usize, ns: &[usize],
       size_rows: &mut String, lat_rows: &mut String) {
    let name = format!("{alg:?}");
    let root = KeyPair::new_with_algorithm(alg);

    // ---- size sweep (always 0..=20) ----
    for n in 0..=MAX_N {
        let token = make_token(&root, alg, n);
        let unsealed = token.to_vec().expect("unsealed serialize");
        let sealed = token.seal().expect("seal").to_vec().expect("sealed serialize");
        size_rows.push_str(&format!("{name},{n},{},{}\n", unsealed.len(), sealed.len()));
    }

    // ---- latency sweep ----
    for &n in ns {
        let t_auth = median_ns(reps, warmup, || {
            Biscuit::builder()
                .fact("right(\"file1\", \"read\")")
                .unwrap()
                .fact("right(\"file1\", \"write\")")
                .unwrap()
                .build(&root)
                .unwrap()
        });
        lat_rows.push_str(&format!("{name},{n},authority_build,{t_auth},{reps}\n"));

        let base = make_token(&root, alg, n);
        let t_append = median_ns(reps, warmup, || {
            let kp = KeyPair::new_with_algorithm(alg);
            base.append_with_keypair(&kp, atten_block()).unwrap()
        });
        lat_rows.push_str(&format!("{name},{n},append_hop,{t_append},{reps}\n"));

        let unsealed = make_token(&root, alg, n);
        let t_seal = median_ns(reps, warmup, || unsealed.seal().unwrap());
        lat_rows.push_str(&format!("{name},{n},seal,{t_seal},{reps}\n"));

        let sealed_bytes = make_token(&root, alg, n)
            .seal()
            .unwrap()
            .to_vec()
            .unwrap();
        let t_verify = median_ns(reps, warmup, || {
            Biscuit::from(&sealed_bytes, root.public()).unwrap()
        });
        lat_rows.push_str(&format!("{name},{n},verify_chain,{t_verify},{reps}\n"));

        let parsed = Biscuit::from(&sealed_bytes, root.public()).unwrap();
        let t_authz = median_ns(reps, warmup, || {
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
        lat_rows.push_str(&format!("{name},{n},authorize,{t_authz},{reps}\n"));
    }

    println!("[{name:>11}] size 0..={MAX_N}, latency {reps} reps x {} n-values done", ns.len());
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut size_rows = String::from("alg,n,unsealed_bytes,sealed_bytes\n");
    let mut lat_rows = String::from("alg,n,phase,median_ns,reps\n");

    // fast schemes: full latency grid
    for alg in [
        Algorithm::Ed25519,
        Algorithm::Mldsa44,
        Algorithm::Mldsa65,
        Algorithm::Mldsa87,
        Algorithm::Fndsa512,
        Algorithm::Fndsa1024,
    ] {
        run(alg, FAST_REPS, 10, &FAST_NS, &mut size_rows, &mut lat_rows);
    }
    // slow hash-based schemes: reduced reps and n grid (size sweep still full)
    for alg in [
        Algorithm::Slhdsa128s,
        Algorithm::Slhdsa128f,
        Algorithm::Slhdsa256s,
        Algorithm::Slhdsa256f,
    ] {
        run(alg, SLOW_REPS, 1, &SLOW_NS, &mut size_rows, &mut lat_rows);
    }

    let out = "../../experiments/data";
    fs::create_dir_all(out)?;
    fs::write(format!("{out}/e55_token_size.csv"), size_rows)?;
    fs::write(format!("{out}/e55_latency.csv"), lat_rows)?;
    println!("wrote {out}/e55_token_size.csv and e55_latency.csv");
    Ok(())
}
