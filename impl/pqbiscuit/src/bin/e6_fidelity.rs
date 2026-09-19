//! E6-A functional-fidelity and security-binding matrix for the PQ migration.
//!
//! For EVERY signature algorithm (Ed25519 + 9 NIST PQ parameter sets + 2 hybrid
//! combos) this verifies that migrating the signature primitive does not change
//! Biscuit's token semantics or security bindings:
//!   f1 seal+attenuate+verify   authority facts, 2 attenuation hops, seal, parse, Datalog allow
//!   f2 datalog_write_denied     the attenuation check still forbids `write`
//!   f3 unsealed_roundtrip      an unsealed token serialises/parses and can keep attenuating
//!   f4 key_bytes_roundtrip     private/public key byte (de)serialisation reconstructs the key
//!   f5 wrong_root_rejected     a verifier holding a different root public key rejects
//!   f6 tamper_rejected         byte flips at 5 positions across the sealed token all reject
//!   f7 third_party_pq          a third-party block signed with the SAME PQ/hybrid key verifies
//!   f8 third_party_wrong_key   mismatched external public key is rejected at append
//!   f9 hybrid_cross_combo       (hybrid only) verifying one combo with another root rejects
//!
//! Output: experiments/data/e6_fidelity.csv  (alg,check,result,detail)
//! Exits non-zero if any check FAILs.

use std::error::Error;
use std::fs;

use biscuit_auth::builder_ext::AuthorizerExt;
use biscuit_auth::{Algorithm, AuthorizerBuilder, Biscuit, BlockBuilder, KeyPair, PrivateKey, PublicKey};

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

fn authorize_op(t: &Biscuit, op: &str) -> Result<usize, Box<dyn Error>> {
    let opfact = format!("operation(\"{op}\")");
    let b = AuthorizerBuilder::new()
        .fact("resource(\"file1\")")?
        .fact(opfact.as_str())?
        .allow_all();
    Ok(b.build(t)?.authorize()?)
}

fn rec(out: &mut String, alg: &str, check: &str, ok: bool, detail: String) -> bool {
    let d = detail.replace('"', "\"\"");
    out.push_str(&format!("{alg},{check},{},\"{d}\"\n", if ok { "PASS" } else { "FAIL" }));
    if !ok { eprintln!("  [FAIL] {alg} {check}: {detail}"); }
    ok
}

fn main() -> Result<(), Box<dyn Error>> {
    let algs = [
        Algorithm::Ed25519, Algorithm::Mldsa44, Algorithm::Mldsa65, Algorithm::Mldsa87,
        Algorithm::Fndsa512, Algorithm::Fndsa1024,
        Algorithm::HybridEdMldsa44, Algorithm::HybridEdFndsa512,
        Algorithm::Slhdsa128s, Algorithm::Slhdsa128f,
        Algorithm::Slhdsa256s, Algorithm::Slhdsa256f,
    ];
    let mut out = String::from("alg,check,result,detail\n");
    let mut failures = 0usize;
    let filter: Option<String> = std::env::args().nth(1);

    for alg in algs {
        let name = format!("{alg:?}");
        if let Some(f) = &filter { if !name.to_lowercase().contains(&f.to_lowercase()) { continue; } }
        let root = KeyPair::new_with_algorithm(alg);
        let mut allok = true;

        // f1: full happy path, Datalog read allowed
        let sealed = build(&root, alg, 2).seal()?.to_vec()?;
        let tok = Biscuit::from(&sealed, root.public())?;
        let allowed = authorize_op(&tok, "read").is_ok();
        allok &= rec(&mut out, &name, "f1_seal_atten_verify", allowed,
                     "authority+2 hops sealed, parsed, read authorized".into());

        // f2: write denied by attenuation check
        let denied = authorize_op(&tok, "write").is_err();
        allok &= rec(&mut out, &name, "f2_datalog_write_denied", denied,
                     "write must be rejected by attenuation check".into());

        // f3: unsealed round-trip then keep attenuating and verify
        let u = build(&root, alg, 1);
        let bytes = u.to_vec()?;
        let parsed = Biscuit::from(&bytes, root.public())?;
        let kp = KeyPair::new_with_algorithm(alg);
        let u2 = parsed.append_with_keypair(&kp, atten())?;
        let rt = u2.seal()?.to_vec()?;
        let tok3 = Biscuit::from(&rt, root.public())?;
        let rt_ok = authorize_op(&tok3, "read").is_ok();
        allok &= rec(&mut out, &name, "f3_unsealed_roundtrip", rt_ok,
                     "unsealed serialise/parse, re-attenuate, seal, verify".into());

        // f4: private/public key byte round-trip
        let sk = root.private();
        let skb = sk.to_bytes();
        let sk2 = PrivateKey::from_bytes(&skb, alg)?;
        let kp2 = KeyPair::from(&sk2);
        let pkb = root.public().to_bytes();
        let pk2 = PublicKey::from_bytes(&pkb, alg)?;
        let keyok = kp2.public() == root.public() && pk2 == root.public() && !pkb.is_empty();
        allok &= rec(&mut out, &name, "f4_key_bytes_roundtrip", keyok,
                     format!("sk {} B, pk {} B round-trip equal", skb.len(), pkb.len()));

        // f5: wrong root rejected
        let other = KeyPair::new_with_algorithm(alg);
        let wrong = Biscuit::from(&sealed, other.public()).is_err();
        allok &= rec(&mut out, &name, "f5_wrong_root_rejected", wrong,
                     "parse with unrelated same-algorithm root public key fails".into());

        // f6: tamper at 5 spread positions -> every flip rejected
        let mut tam_ok = true;
        let mut ndetail = Vec::new();
        for frac in [0.05, 0.25, 0.50, 0.75, 0.99] {
            let mut b = sealed.clone();
            let idx = ((b.len() as f64) * frac) as usize;
            b[idx] ^= 0xFF;
            let rejected = match Biscuit::from(&b, root.public()) {
                Ok(t) => authorize_op(&t, "read").is_err(),
                Err(_) => true,
            };
            if !rejected { tam_ok = false; ndetail.push(format!("idx{idx}")); }
        }
        allok &= rec(&mut out, &name, "f6_tamper_rejected", tam_ok,
                     if tam_ok { "all 5 byte flips rejected".into() }
                     else { format!("accepted flips at {:?}", ndetail) });

        // f7: third-party block signed by a PQ/hybrid key verifies through the chain
        let f7res: Result<(), String> = (|| {
            // base with one EMPTY attenuation block (no block-level check), so the
            // test isolates third-party external-signature binding (allow_all suffices)
            let mut base = Biscuit::builder().fact("right(\"file1\", \"read\")")
                .map_err(|e| format!("build: {e:?}"))?.build(&root)
                .map_err(|e| format!("auth: {e:?}"))?;
            base = base.append_with_keypair(&KeyPair::new_with_algorithm(alg), BlockBuilder::new())
                .map_err(|e| format!("hop: {e:?}"))?;
            let third = KeyPair::new_with_algorithm(alg);
            let next = KeyPair::new_with_algorithm(alg);
            let req = base.third_party_request().map_err(|e| format!("req: {e:?}"))?;
            let bb = BlockBuilder::new().fact("third_party_grant(\"tp\")").map_err(|e| format!("bb: {e:?}"))?;
            let resp = req.create_block(&third.private(), bb).map_err(|e| format!("create: {e:?}"))?;
            let with_tp = base
                .append_third_party_with_keypair(third.public(), resp, next)
                .map_err(|e| format!("append: {e:?}"))?;
            let tp_sealed = with_tp.seal().map_err(|e| format!("seal: {e:?}"))?
                .to_vec().map_err(|e| format!("vec: {e:?}"))?;
            let tp_tok = Biscuit::from(&tp_sealed, root.public()).map_err(|e| format!("from: {e:?}"))?;
            let mut auth = AuthorizerBuilder::new().allow_all().build(&tp_tok)
                .map_err(|e| format!("buildauth: {e:?}"))?;
            auth.authorize().map(|_| ()).map_err(|e| format!("authorize: {e:?}"))
        })();
        allok &= rec(&mut out, &name, "f7_third_party_pq", f7res.is_ok(),
                     match &f7res { Ok(()) => "third-party block verifies".into(),
                                   Err(e) => format!("third-party error -> {e}") });

        // f8: third-party append with mismatched external public key rejected
        let base2 = build(&root, alg, 1);
        let third2 = KeyPair::new_with_algorithm(alg);
        let wrong_ext = KeyPair::new_with_algorithm(alg);
        let next2 = KeyPair::new_with_algorithm(alg);
        let req2 = base2.third_party_request()?;
        let resp2 = req2.create_block(
            &third2.private(),
            BlockBuilder::new().fact("third_party_grant(\"tp\")")?)?;
        let tp_wrong = base2
            .append_third_party_with_keypair(wrong_ext.public(), resp2, next2)
            .is_err();
        allok &= rec(&mut out, &name, "f8_third_party_wrong_key", tp_wrong,
                     "external key != signing key rejected at append".into());

        // f9 (hybrid only): cross-combo verification rejected
        if matches!(alg, Algorithm::HybridEdMldsa44 | Algorithm::HybridEdFndsa512) {
            let other_combo = if alg == Algorithm::HybridEdMldsa44 {
                KeyPair::new_with_algorithm(Algorithm::HybridEdFndsa512)
            } else {
                KeyPair::new_with_algorithm(Algorithm::HybridEdMldsa44)
            };
            let cross = Biscuit::from(&sealed, other_combo.public()).is_err();
            allok &= rec(&mut out, &name, "f9_hybrid_cross_combo", cross,
                         "token of one hybrid combo rejected under the other combo root".into());
        }

        if !allok { failures += 1; }
        println!("[{name:>17}] {}", if allok { "ALL PASS" } else { "HAS FAIL" });
    }

    let outdir = "../../experiments/data";
    fs::create_dir_all(outdir)?;
    fs::write(format!("{outdir}/e6_fidelity.csv"), out)?;
    println!("\nwrote e6_fidelity.csv; algorithms with failures = {failures}");
    if failures > 0 { std::process::exit(1); }
    Ok(())
}
