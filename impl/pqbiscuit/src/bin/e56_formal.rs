//! E5-6 formal, single-threaded measurement harness.
//!
//! Produces RAW timing samples (one row per repetition) so the analysis stage
//! can report median, Q1/Q3 (IQR) and extrema rather than a single median.
//! Run pinned to one physical core (taskset -c) for a stable single-thread
//! figure. Two builds are measured: the default AVX2 PQClean kernels and a
//! portable `clean` C build (pqcrypto crates with `default-features = false,
//! features = ["std"]`); the build tag is argv[1] (avx2|portable).
//!
//! Outputs (experiments/data):
//!   e56_latency_<tag>.csv  : alg,op,n,ns           (raw samples)
//!   e56_size_<tag>.csv     : alg,n,unsealed,sealed (deterministic)
//!   e56_fnlen_<tag>.csv    : alg,iter,sealed_n0    (FN variable-length spread)
//!
//! Run: `taskset -c 2 cargo run --release --bin e56_formal -- avx2`.

use std::error::Error;
use std::fs;
use std::hint::black_box;
use std::time::Instant;

use biscuit_auth::builder_ext::AuthorizerExt;
use biscuit_auth::{Algorithm, AuthorizerBuilder, Biscuit, BlockBuilder, KeyPair};

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

/// collect `reps` raw nanosecond samples after `warmup` discarded iterations
fn samples<R>(reps: usize, warmup: usize, mut f: impl FnMut() -> R) -> Vec<u128> {
    for _ in 0..warmup {
        black_box(f());
    }
    let mut out = Vec::with_capacity(reps);
    for _ in 0..reps {
        let t = Instant::now();
        let r = f();
        black_box(r);
        out.push(t.elapsed().as_nanos());
    }
    out
}

fn main() -> Result<(), Box<dyn Error>> {
    let tag = std::env::args().nth(1).unwrap_or_else(|| "avx2".to_string());

    let fast = [
        Algorithm::Ed25519,
        Algorithm::Mldsa44,
        Algorithm::Mldsa65,
        Algorithm::Mldsa87,
        Algorithm::Fndsa512,
        Algorithm::Fndsa1024,
        Algorithm::HybridEdMldsa44,
        Algorithm::HybridEdFndsa512,
    ];
    let slow = [
        Algorithm::Slhdsa128s,
        Algorithm::Slhdsa128f,
        Algorithm::Slhdsa256s,
        Algorithm::Slhdsa256f,
    ];
    let all: Vec<Algorithm> = fast.iter().chain(slow.iter()).copied().collect();

    let mut lat = String::from("alg,op,n,ns\n");
    let mut size = String::from("alg,n,unsealed_bytes,sealed_bytes\n");
    let mut fnlen = String::from("alg,iter,sealed_n0\n");

    // ---- deterministic size sweep n=0..=10 ----
    for &alg in &all {
        let name = format!("{alg:?}");
        let root = KeyPair::new_with_algorithm(alg);
        for n in 0..=10usize {
            let t = make_token(&root, alg, n);
            let unsealed = t.to_vec().unwrap().len();
            let sealed = t.seal().unwrap().to_vec().unwrap().len();
            size.push_str(&format!("{name},{n},{unsealed},{sealed}\n"));
        }
    }

    // ---- latency: verify slope grid + five phases at n=2 ----
    let measure = |alg: Algorithm, reps: usize, warmup: usize, vns: &[usize],
                   lat: &mut String| {
        let name = format!("{alg:?}");
        let root = KeyPair::new_with_algorithm(alg);

        for &n in vns {
            let sealed = make_token(&root, alg, n).seal().unwrap().to_vec().unwrap();
            for v in samples(reps, warmup, || Biscuit::from(&sealed, root.public()).unwrap()) {
                lat.push_str(&format!("{name},verify_chain,{n},{v}\n"));
            }
        }

        let n = 2usize;
        for v in samples(reps, warmup, || {
            Biscuit::builder()
                .fact("right(\"file1\", \"read\")").unwrap()
                .fact("right(\"file1\", \"write\")").unwrap()
                .build(&root).unwrap()
        }) {
            lat.push_str(&format!("{name},authority_build,{n},{v}\n"));
        }

        let base = make_token(&root, alg, n);
        for v in samples(reps, warmup, || {
            let kp = KeyPair::new_with_algorithm(alg);
            base.append_with_keypair(&kp, atten_block()).unwrap()
        }) {
            lat.push_str(&format!("{name},append_hop,{n},{v}\n"));
        }

        let unsealed = make_token(&root, alg, n);
        for v in samples(reps, warmup, || unsealed.seal().unwrap()) {
            lat.push_str(&format!("{name},seal,{n},{v}\n"));
        }

        let sealed_bytes = make_token(&root, alg, n).seal().unwrap().to_vec().unwrap();
        for v in samples(reps, warmup, || Biscuit::from(&sealed_bytes, root.public()).unwrap()) {
            lat.push_str(&format!("{name},verify_n2,{n},{v}\n"));
        }

        let parsed = Biscuit::from(&sealed_bytes, root.public()).unwrap();
        for v in samples(reps, warmup, || {
            AuthorizerBuilder::new()
                .fact("resource(\"file1\")").unwrap()
                .fact("operation(\"read\")").unwrap()
                .allow_all()
                .build(&parsed).unwrap()
                .authorize().unwrap()
        }) {
            lat.push_str(&format!("{name},authorize,{n},{v}\n"));
        }
        println!("[{name:>17}] {reps} reps done ({tag})");
    };

    for &alg in &fast {
        measure(alg, 101, 15, &[0, 1, 2, 5, 10], &mut lat);
    }
    for &alg in &slow {
        measure(alg, 5, 1, &[0, 1, 2], &mut lat);
    }

    // ---- FN-DSA variable signature-length spread (sealed n=0, 51 trials) ----
    for alg in [Algorithm::Fndsa512, Algorithm::Fndsa1024, Algorithm::HybridEdFndsa512] {
        let name = format!("{alg:?}");
        for i in 0..51 {
            let root = KeyPair::new_with_algorithm(alg);
            let sealed = make_token(&root, alg, 0).seal().unwrap().to_vec().unwrap().len();
            fnlen.push_str(&format!("{name},{i},{sealed}\n"));
        }
    }

    let out = "../../experiments/data";
    fs::create_dir_all(out)?;
    fs::write(format!("{out}/e56_latency_{tag}.csv"), lat)?;
    fs::write(format!("{out}/e56_size_{tag}.csv"), size)?;
    fs::write(format!("{out}/e56_fnlen_{tag}.csv"), fnlen)?;
    println!("wrote e56_*_{tag}.csv");
    Ok(())
}
