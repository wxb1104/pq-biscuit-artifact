//! E6-B fresh-key pre-generation amortisation.
//!
//! Biscuit mints a FRESH key pair at every attenuation hop and signs the next-key
//! binding. For FN-DSA / SLH-DSA key generation is non-trivial; because tokens are
//! attenuated OFFLINE, attenuation key pairs can be pre-minted in a batch and the
//! online per-hop cost collapses to a single signature.
//!
//! On a fixed-length base token (n = 2), per rep we time three black boxes:
//!   keygen           : KeyPair::new_with_algorithm(alg)
//!   append_realtime  : keygen + append_with_keypair (the naive online path)
//!   append_sign      : append_with_keypair with a PRE-MINTED key pair (online path)
//! The two append boxes are identical except that realtime includes key generation,
//! so append_realtime ~= keygen + append_sign (additivity is checked in analysis).
//!
//! Output: experiments/data/e6_pregen.csv  (alg,phase,rep,ns)  raw samples.

use std::error::Error;
use std::fs;
use std::hint::black_box;
use std::time::Instant;

use biscuit_auth::{Algorithm, Biscuit, BlockBuilder, KeyPair};

fn atten() -> BlockBuilder {
    BlockBuilder::new().check("check if operation(\"read\")").unwrap()
}

fn build(root: &KeyPair, alg: Algorithm, n: usize) -> Biscuit {
    let mut t = Biscuit::builder().fact("right(\"file1\", \"read\")").unwrap().build(root).unwrap();
    for _ in 0..n {
        t = t.append_with_keypair(&KeyPair::new_with_algorithm(alg), atten()).unwrap();
    }
    t
}

fn main() -> Result<(), Box<dyn Error>> {
    let fast = [
        Algorithm::Ed25519, Algorithm::Mldsa44, Algorithm::Mldsa65, Algorithm::Mldsa87,
        Algorithm::Fndsa512, Algorithm::Fndsa1024,
        Algorithm::HybridEdMldsa44, Algorithm::HybridEdFndsa512,
    ];
    let slow = [Algorithm::Slhdsa128s, Algorithm::Slhdsa128f, Algorithm::Slhdsa256s, Algorithm::Slhdsa256f];

    let mut out = String::from("alg,phase,rep,ns\n");

    let run = |alg: Algorithm, reps: u32, warm: u32, out: &mut String| {
        let root = KeyPair::new_with_algorithm(alg);
        let base = build(&root, alg, 2);
        let total = reps + warm;

        // pre-mint key pairs OUTSIDE the sign-only timing box (block builder is
        // also constructed before the box so only the signature is measured)
        let pool: Vec<KeyPair> = (0..total).map(|_| KeyPair::new_with_algorithm(alg)).collect();

        for r in 0..total {
            let t0 = Instant::now();
            let kp = KeyPair::new_with_algorithm(alg);
            black_box(&kp);
            let ns = t0.elapsed().as_nanos();
            if r >= warm { out.push_str(&format!("{alg:?},keygen,{},{ns}\n", r - warm)); }
        }
        for r in 0..total {
            let b = base.clone();
            let t0 = Instant::now();
            let kp = KeyPair::new_with_algorithm(alg);
            let t = b.append_with_keypair(&kp, atten()).unwrap();
            black_box(&t);
            let ns = t0.elapsed().as_nanos();
            if r >= warm { out.push_str(&format!("{alg:?},append_realtime,{},{ns}\n", r - warm)); }
        }
        for r in 0..total {
            let b = base.clone();
            let kp = &pool[r as usize];
            let bb = atten();
            let t0 = Instant::now();
            let t = b.append_with_keypair(kp, bb).unwrap();
            black_box(&t);
            let ns = t0.elapsed().as_nanos();
            if r >= warm { out.push_str(&format!("{alg:?},append_sign,{},{ns}\n", r - warm)); }
        }
        println!("[{alg:?}] {reps} reps done");
    };

    for a in fast { run(a, 101, 15, &mut out); }
    for a in slow { run(a, 21, 3, &mut out); }

    let outdir = "../../experiments/data";
    fs::create_dir_all(outdir)?;
    fs::write(format!("{outdir}/e6_pregen.csv"), out)?;
    println!("wrote e6_pregen.csv");
    Ok(())
}
