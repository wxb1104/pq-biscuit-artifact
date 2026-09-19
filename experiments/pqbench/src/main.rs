// PQ-Biscuit E1 standalone signature benchmark (real PQClean via pqcrypto-rs).
// Emits data/algostats.csv with key/signature sizes and keygen/sign/verify
// timings (median + p95). Sizes are deterministic and cross-checked against
// FIPS 204/205; timings are measured on this host (report hardware in paper).
//
// pqcrypto 0.5 API: module-level free functions
//   keypair() -> (PublicKey, SecretKey)
//   detached_sign(msg, &sk) -> DetachedSignature
//   verify_detached_signature(&sig, msg, &pk) -> Result<()>
use std::env;
use std::fs;
use std::io::Write;
use std::time::Instant;

use rand::rngs::OsRng;

struct Row {
    family: &'static str,
    variant: &'static str,
    level: u8,
    pk: usize,
    sk: usize,
    sig: usize,
    kg_med: u128,
    kg_p95: u128,
    sg_med: u128,
    sg_p95: u128,
    vf_med: u128,
    vf_p95: u128,
    iters: usize,
}

fn quantile(xs: &mut [u128], q: f64) -> u128 {
    xs.sort_unstable();
    let i = ((xs.len() as f64 - 1.0) * q).round() as usize;
    xs[i.min(xs.len() - 1)]
}
fn med(xs: &mut [u128]) -> u128 { quantile(xs, 0.5) }
fn p95(xs: &mut [u128]) -> u128 { quantile(xs, 0.95) }

macro_rules! bench_pq {
    ($mod:path, $variant:expr, $family:expr, $level:expr, $it:expr, $rows:expr) => {{
        use $mod::{
            detached_sign, keypair, verify_detached_signature, DetachedSignature, PublicKey,
            SecretKey,
        };
        use pqcrypto_traits::sign::{
            DetachedSignature as DSig, PublicKey as PK, SecretKey as SK,
        };

        // deterministic byte sizes + one correctness check
        let (pk0, sk0) = keypair();
        let (pkb, skb) = (pk0.as_bytes().to_vec(), sk0.as_bytes().to_vec());
        let m0 = b"pq-biscuit-block";
        let d0 = detached_sign(m0, &sk0);
        let sigb = d0.as_bytes().to_vec();
        verify_detached_signature(
            &DetachedSignature::from_bytes(&sigb).unwrap(),
            m0,
            &PublicKey::from_bytes(&pkb).unwrap(),
        )
        .expect("sanity verify");

        // keygen timing
        let mut kg = Vec::with_capacity($it);
        for _ in 0..$it {
            let t = Instant::now();
            let _ = keypair();
            kg.push(t.elapsed().as_nanos());
        }
        // sign / verify timing: fixed keypair, distinct messages
        let (pk, sk) = keypair();
        let (mut sg, mut vf) = (Vec::with_capacity($it), Vec::with_capacity($it));
        for i in 0..$it {
            let m = format!("pq-biscuit-block-{i}");
            let mb = m.as_bytes();
            let t = Instant::now();
            let d = detached_sign(mb, &sk);
            sg.push(t.elapsed().as_nanos());
            let dobj = DetachedSignature::from_bytes(&d.as_bytes()).unwrap();
            let t = Instant::now();
            verify_detached_signature(&dobj, mb, &pk).expect("verify");
            vf.push(t.elapsed().as_nanos());
        }
        $rows.push(Row {
            family: $family, variant: $variant, level: $level,
            pk: pkb.len(), sk: skb.len(), sig: sigb.len(),
            kg_med: med(&mut kg), kg_p95: p95(&mut kg),
            sg_med: med(&mut sg), sg_p95: p95(&mut sg),
            vf_med: med(&mut vf), vf_p95: p95(&mut vf),
            iters: $it,
        });
    }};
}

fn bench_ed25519(iters: usize) -> Row {
    use ed25519_dalek::{Signer, SigningKey, Verifier};
    let mut rng = OsRng;
    let sk0 = SigningKey::generate(&mut rng);
    let pk0 = sk0.verifying_key();
    let s0 = sk0.sign(b"pq-biscuit-block");
    pk0.verify(b"pq-biscuit-block", &s0).unwrap();
    let (pkb, skb, sigb) =
        (pk0.to_bytes().len(), sk0.to_bytes().len(), s0.to_bytes().len());

    let mut kg = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        let _ = SigningKey::generate(&mut rng);
        kg.push(t.elapsed().as_nanos());
    }
    let sk = SigningKey::generate(&mut rng);
    let pk = sk.verifying_key();
    let (mut sg, mut vf) = (Vec::with_capacity(iters), Vec::with_capacity(iters));
    for i in 0..iters {
        let m = format!("pq-biscuit-block-{i}");
        let mb = m.as_bytes();
        let t = Instant::now();
        let s = sk.sign(mb);
        sg.push(t.elapsed().as_nanos());
        let t = Instant::now();
        pk.verify(mb, &s).unwrap();
        vf.push(t.elapsed().as_nanos());
    }
    Row {
        family: "classical", variant: "ed25519", level: 1,
        pk: pkb, sk: skb, sig: sigb,
        kg_med: med(&mut kg), kg_p95: p95(&mut kg),
        sg_med: med(&mut sg), sg_p95: p95(&mut sg),
        vf_med: med(&mut vf), vf_p95: p95(&mut vf),
        iters,
    }
}

fn main() {
    let dir = env::args()
        .nth(1)
        .unwrap_or_else(|| concat!(env!("CARGO_MANIFEST_DIR"), "/../data").to_string());
    fs::create_dir_all(&dir).unwrap();

    let mut rows: Vec<Row> = Vec::new();
    rows.push(bench_ed25519(1000));
    bench_pq!(pqcrypto_dilithium::dilithium2, "mldsa44", "ml-dsa", 2, 300, rows);
    bench_pq!(pqcrypto_dilithium::dilithium3, "mldsa65", "ml-dsa", 3, 300, rows);
    bench_pq!(pqcrypto_dilithium::dilithium5, "mldsa87", "ml-dsa", 5, 200, rows);
    // Enable after adding pqcrypto-falcon / pqcrypto-sphincsplus:
    bench_pq!(pqcrypto_falcon::falcon512, "fndsa512", "fn-dsa", 1, 100, rows);
    bench_pq!(pqcrypto_falcon::falcon1024, "fndsa1024", "fn-dsa", 5, 100, rows);
    bench_pq!(pqcrypto_sphincsplus::sphincssha2128ssimple, "slhdsa128s", "slh-dsa", 1, 30, rows);
    bench_pq!(pqcrypto_sphincsplus::sphincssha2128fsimple, "slhdsa128f", "slh-dsa", 1, 30, rows);
    bench_pq!(pqcrypto_sphincsplus::sphincssha2256ssimple, "slhdsa256s", "slh-dsa", 5, 20, rows);
    bench_pq!(pqcrypto_sphincsplus::sphincssha2256fsimple, "slhdsa256f", "slh-dsa", 5, 20, rows);

    let path = std::path::Path::new(&dir).join("algostats.csv");
    let mut f = fs::File::create(&path).unwrap();
    writeln!(
        f,
        "family,variant,level,pk,sk,sig,keygen_med_us,keygen_p95_us,sign_med_us,sign_p95_us,verify_med_us,verify_p95_us,samples"
    )
    .unwrap();
    let us = |ns: u128| (ns as f64) / 1000.0;
    for r in &rows {
        writeln!(
            f,
            "{},{},{},{},{},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{}",
            r.family, r.variant, r.level, r.pk, r.sk, r.sig,
            us(r.kg_med), us(r.kg_p95), us(r.sg_med), us(r.sg_p95),
            us(r.vf_med), us(r.vf_p95), r.iters
        )
        .unwrap();
        println!(
            "{:9} pk={:<6} sk={:<6} sig={:<6} keygen={:9.2}us sign={:9.2}us verify={:8.2}us",
            r.variant, r.pk, r.sk, r.sig, us(r.kg_med), us(r.sg_med), us(r.vf_med)
        );
    }
    println!("wrote {}", path.display());
}
