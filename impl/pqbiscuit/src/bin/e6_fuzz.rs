//! E6-B large-sample, property-based adversarial fuzzing of the sealed token.
//!
//! Complements the hand-written f1--f11 checks with a high-volume, deterministic
//! mutation campaign. For every algorithm, a sealed n=2 token is subjected to
//! five classes of mutation, each repeated K times with a fixed-seed PRNG:
//!   flip     single authenticated byte overwritten with a different value
//!   truncate random length prefix retained
//!   insert   1..4 random bytes inserted at a random position
//!   delete   1..4 bytes removed at a random position
//!   splice   a random region overwritten by the corresponding region of a
//!            DIFFERENT-root token of the same algorithm
//! Every mutation that changes the token must be rejected: we count both
//! parse-level escapes (Biscuit::from succeeds) and full authorization escapes
//! (from succeeds AND a read request is authorized). Both must be zero.
//!
//! Output: experiments/data/e6_fuzz.csv  (alg,mutation,trials,parse_escaped,auth_escaped)
//! Exits non-zero if any mutation escapes.

use std::error::Error;
use std::fs;

use biscuit_auth::builder_ext::AuthorizerExt;
use biscuit_auth::{Algorithm, AuthorizerBuilder, Biscuit, BlockBuilder, KeyPair, PublicKey};

#[derive(Clone, Copy)]
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x.wrapping_shl(13);
        x ^= x.wrapping_shr(7);
        x ^= x.wrapping_shl(17);
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
}

fn atten() -> BlockBuilder {
    BlockBuilder::new().check("check if operation(\"read\")").unwrap()
}

fn build(root: &KeyPair, alg: Algorithm, n: usize) -> Biscuit {
    let mut t = Biscuit::builder()
        .fact("right(\"file1\", \"read\")").unwrap()
        .fact("right(\"file1\", \"write\")").unwrap()
        .build(root).unwrap();
    for _ in 0..n {
        let kp = KeyPair::new_with_algorithm(alg);
        t = t.append_with_keypair(&kp, atten()).unwrap();
    }
    t
}

fn read_authorized(t: &Biscuit) -> bool {
    let b = AuthorizerBuilder::new()
        .fact("resource(\"file1\")").unwrap()
        .fact("operation(\"read\")").unwrap()
        .allow_all();
    b.build(t).unwrap().authorize().is_ok()
}

// Returns (parse_escaped, auth_escaped) for a mutated byte vector.
fn escapes(bytes: &[u8], root: &PublicKey) -> (bool, bool) {
    match Biscuit::from(bytes.to_vec(), root) {
        Ok(t) => (true, read_authorized(&t)),
        Err(_) => (false, false),
    }
}

fn mutate(rng: &mut Rng, base: &[u8], donor: &[u8], kind: &str) -> Vec<u8> {
    let mut b = base.to_vec();
    match kind {
        "flip" => {
            let i = rng.below(b.len());
            let mut v = rng.below(256) as u8;
            if v == b[i] { v ^= 0xFF; }
            b[i] = v;
        }
        "truncate" => {
            let l = 1 + rng.below(b.len().saturating_sub(1).max(1));
            b.truncate(l.min(b.len()));
        }
        "insert" => {
            let i = rng.below(b.len() + 1);
            let k = 1 + rng.below(4);
            let bytes: Vec<u8> = (0..k).map(|_| rng.below(256) as u8).collect();
            b.splice(i..i, bytes);
        }
        "delete" => {
            let i = rng.below(b.len());
            let k = 1 + rng.below(4).min(b.len() - i - 1);
            let k = k.min(b.len() - i);
            b.splice(i..i + k, std::iter::empty());
        }
        "splice" => {
            // overwrite a region with donor bytes, retrying until the token changes
            for _ in 0..16 {
                let k = 1 + rng.below(8).min(b.len() - 1).min(donor.len() - 1);
                let i = rng.below(b.len() - k);
                let j = rng.below(donor.len() - k);
                let mut cand = b.clone();
                cand[i..i + k].copy_from_slice(&donor[j..j + k]);
                if cand != base { b = cand; break; }
            }
        }
        _ => {}
    }
    b
}

fn main() -> Result<(), Box<dyn Error>> {
    let algs = [
        Algorithm::Ed25519, Algorithm::Mldsa44, Algorithm::Mldsa65, Algorithm::Mldsa87,
        Algorithm::Fndsa512, Algorithm::Fndsa1024,
        Algorithm::HybridEdMldsa44, Algorithm::HybridEdFndsa512,
        Algorithm::Slhdsa128s, Algorithm::Slhdsa128f,
        Algorithm::Slhdsa256s, Algorithm::Slhdsa256f,
    ];
    const K: usize = 100;
    let kinds = ["flip", "truncate", "insert", "delete", "splice"];
    let mut out = String::from("alg,mutation,trials,parse_escaped,auth_escaped\n");
    let mut total_esc = 0usize;

    for alg in algs {
        let name = format!("{alg:?}");
        let root = KeyPair::new_with_algorithm(alg);
        let base = build(&root, alg, 2).seal()?.to_vec()?;
        let donor_root = KeyPair::new_with_algorithm(alg);
        let donor = build(&donor_root, alg, 2).seal()?.to_vec()?;

        for kind in kinds {
            let mut rng = Rng(0x9E3779B97F4A7C15 ^ ((name.len() as u64) << 32) ^ (kind.len() as u64));
            let (mut pe, mut ae) = (0usize, 0usize);
            let mut trials = 0usize;
            for _ in 0..K {
                let m = mutate(&mut rng, &base, &donor, kind);
                if &m[..] == &base[..] { continue; } // no-op mutation, do not count
                trials += 1;
                let (p, a) = escapes(&m, &root.public());
                if p { pe += 1; }
                if a { ae += 1; }
            }
            total_esc += pe + ae;
            out.push_str(&format!("{name},{kind},{trials},{pe},{ae}\n"));
            print!("{name:>17} {kind:<9} trials={trials:<4} parse_esc={pe} auth_esc={ae}\n");
        }
    }

    let outdir = "../../experiments/data";
    fs::create_dir_all(outdir)?;
    fs::write(format!("{outdir}/e6_fuzz.csv"), out)?;
    println!("\nwrote e6_fuzz.csv; total escapes = {total_esc} over {} algorithms", algs.len());
    if total_esc > 0 { std::process::exit(1); }
    Ok(())
}
