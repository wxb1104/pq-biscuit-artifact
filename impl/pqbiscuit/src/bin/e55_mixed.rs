//! E5-5 mixed-algorithm chain measurement.
//!
//! Biscuit carries an explicit `algorithm` field in every block's `nextKey`,
//! and `append_with_keypair` signs the new block with the CURRENT proof key
//! while installing the supplied key as the NEXT key. This lets a token
//! transition algorithms with the stock API: a conservative root signs the
//! authority and (unavoidably, via the default same-algorithm first next key)
//! the first attenuation block, after which a smaller/faster scheme signs
//! every subsequent hop and the seal. The root-scheme cost is thus constant
//! (2 signatures) while per-hop cost follows the lighter scheme.
//!
//! For each (root A, attenuation B) pair we record the real sealed size vs n,
//! the whole-chain verification time, and an authorisation/tamper correctness
//! check. Writes data/e55_mixed.csv.
//!
//! Run: `cargo run --release --bin e55_mixed`.

use std::error::Error;
use std::fs;
use std::hint::black_box;
use std::time::Instant;

use biscuit_auth::builder_ext::AuthorizerExt;
use biscuit_auth::{Algorithm, AuthorizerBuilder, Biscuit, BlockBuilder, KeyPair, PublicKey};

const SIZE_N: std::ops::RangeInclusive<usize> = 0..=10;
const VERIFY_N: [usize; 5] = [0, 1, 2, 5, 10];
const REPS: usize = 21;
const WARM: usize = 3;

fn hop() -> BlockBuilder {
    BlockBuilder::new()
        .check("check if operation(\"read\")")
        .expect("check")
}

fn authority(root: &KeyPair) -> Biscuit {
    Biscuit::builder()
        .fact("right(\"file1\", \"read\")")
        .unwrap()
        .fact("right(\"file1\", \"write\")")
        .unwrap()
        .build(root)
        .expect("authority build")
}

/// root algorithm A signs authority + block 1; attenuation algorithm B signs
/// blocks 2..=n and the seal.
fn make_mixed(root: &KeyPair, att_alg: Algorithm, n: usize) -> Biscuit {
    let mut t = authority(root);
    if n >= 1 {
        // block 1 is signed by the authority proof key (A); next key switches to B
        t = t
            .append_with_keypair(&KeyPair::new_with_algorithm(att_alg), hop())
            .expect("transition hop");
        for _ in 1..n {
            t = t
                .append_with_keypair(&KeyPair::new_with_algorithm(att_alg), hop())
                .expect("attenuation hop");
        }
    }
    t
}

fn median_us<R>(reps: usize, warm: usize, mut f: impl FnMut() -> R) -> f64 {
    for _ in 0..warm {
        black_box(f());
    }
    let mut s = Vec::with_capacity(reps);
    for _ in 0..reps {
        let t0 = Instant::now();
        black_box(f());
        s.push(t0.elapsed().as_nanos());
    }
    s.sort_unstable();
    s[s.len() / 2] as f64 / 1e3
}

fn correctness(root: &KeyPair, att_alg: Algorithm) -> bool {
    let mut t = authority(root);
    t = t
        .append_with_keypair(&KeyPair::new_with_algorithm(att_alg), hop())
        .unwrap();
    for _ in 1..3 {
        t = t
            .append_with_keypair(&KeyPair::new_with_algorithm(att_alg), hop())
            .unwrap();
    }
    let sealed = t.seal().unwrap().to_vec().unwrap();
    let v = Biscuit::from(&sealed, root.public()).expect("mixed chain verify");
    let read_ok = AuthorizerBuilder::new()
        .fact("resource(\"file1\")")
        .unwrap()
        .fact("operation(\"read\")")
        .unwrap()
        .allow_all()
        .build(&v)
        .unwrap()
        .authorize()
        .is_ok();
    let write_denied = AuthorizerBuilder::new()
        .fact("resource(\"file1\")")
        .unwrap()
        .fact("operation(\"write\")")
        .unwrap()
        .allow_all()
        .build(&v)
        .unwrap()
        .authorize()
        .is_err();
    let mut bad = sealed.clone();
    let l = bad.len() - 1;
    bad[l] ^= 0xFF;
    let tamper_rejected = Biscuit::from(&bad, root.public()).is_err();
    read_ok && write_denied && tamper_rejected
}

fn main() -> Result<(), Box<dyn Error>> {
    // (conservative root A, lightweight attenuation B)
    let pairs: &[(Algorithm, Algorithm)] = &[
        (Algorithm::Mldsa87, Algorithm::Fndsa512),
        (Algorithm::Slhdsa256s, Algorithm::Fndsa512),
        (Algorithm::Slhdsa128s, Algorithm::Mldsa44),
        (Algorithm::Mldsa87, Algorithm::Mldsa44),
        (Algorithm::Slhdsa128s, Algorithm::Fndsa512),
    ];

    let mut rows = String::from("root,atten,n,sealed_bytes,verify_median_us,reps\n");
    for &(a, b) in pairs {
        let root = KeyPair::new_with_algorithm(a);
        let ok = correctness(&root, b);
        println!("[{a:>11} -> {b:>11}] correctness(read/write/tamper) = {}",
                 if ok { "PASS" } else { "FAIL" });
        assert!(ok, "mixed chain {a:?}->{b:?} failed");

        for n in SIZE_N {
            let sealed = make_mixed(&root, b, n).seal().unwrap().to_vec().unwrap();
            rows.push_str(&format!("{a:?},{b:?},{n},{},,\n", sealed.len()));
        }
        for &n in VERIFY_N.iter() {
            let sealed = make_mixed(&root, b, n).seal().unwrap().to_vec().unwrap();
            let root_pk: PublicKey = root.public();
            let us = median_us(REPS, WARM, || Biscuit::from(&sealed, root_pk).unwrap());
            rows.push_str(&format!("{a:?},{b:?},{n},,{us:.2},{REPS}\n"));
        }
    }

    let out = "../../experiments/data";
    fs::create_dir_all(out)?;
    fs::write(format!("{out}/e55_mixed.csv"), rows)?;
    println!("wrote {out}/e55_mixed.csv");
    Ok(())
}
