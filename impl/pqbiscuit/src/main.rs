//! End-to-end post-quantum Biscuit demonstration.
//!
//! For each signature algorithm (the classical Ed25519 baseline and the
//! post-quantum ML-DSA-44 backend) it:
//!   1. mints an authority block,
//!   2. appends two attenuation blocks with fresh per-hop same-algorithm keys,
//!   3. round-trips the *unsealed* token and appends one more hop (this exercises
//!      ML-DSA private-key recovery, since the PQ secret key is stored as sk||pk),
//!   4. seals the token,
//!   5. verifies the whole signature chain and runs the Datalog authorizer
//!      (one allowed and one correctly-denied request),
//!   6. confirms that a tampered token is rejected.
//!
//! It also prints the real serialized sizes used to calibrate the size model.

use biscuit_auth::builder_ext::AuthorizerExt;
use biscuit_auth::{Algorithm, AuthorizerBuilder, Biscuit, BlockBuilder, KeyPair};

fn run(alg: Algorithm, label: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n================ {label} ({alg:?}) ================");

    // 1. root key + authority block (a PQ root yields a PQ next key automatically)
    let root = KeyPair::new_with_algorithm(alg);
    println!("root public-key size: {} bytes", root.public().to_bytes().len());

    let token = Biscuit::builder()
        .fact("right(\"file1\", \"read\")")?
        .fact("right(\"file1\", \"write\")")?
        .build(&root)?;

    // 2. two attenuation hops, each carrying a fresh same-algorithm next key
    let k2 = KeyPair::new_with_algorithm(alg);
    let token = token.append_with_keypair(
        &k2,
        BlockBuilder::new().check("check if operation(\"read\")")?,
    )?;
    let k3 = KeyPair::new_with_algorithm(alg);
    let token = token.append_with_keypair(
        &k3,
        BlockBuilder::new().check("check if resource($r), right($r, \"read\")")?,
    )?;

    let blocks = token.block_count();
    let unsealed = token.to_vec()?;
    println!("blocks (authority + attenuation): {blocks}");
    println!(
        "UNSEALED token (attenuable; embeds next secret): {} bytes",
        unsealed.len()
    );

    // 3. deserialize the unsealed token and append again (sk||pk recovery for PQ)
    let parsed = Biscuit::from(&unsealed, root.public())?;
    let k4 = KeyPair::new_with_algorithm(alg);
    let extended = parsed.append_with_keypair(
        &k4,
        BlockBuilder::new().check("check if operation(\"read\")")?,
    )?;

    // 4. seal (final asymmetric signature; no secret carried)
    let sealed = token.seal()?.to_vec()?;
    let sealed_ext = extended.seal()?.to_vec()?;
    println!("SEALED token (2 atten hops): {} bytes", sealed.len());
    println!("SEALED token (3 atten hops): {} bytes", sealed_ext.len());

    // 5a. positive authorization: read on file1 must pass
    let t = Biscuit::from(&sealed, root.public())?;
    AuthorizerBuilder::new()
        .fact("resource(\"file1\")")?
        .fact("operation(\"read\")")?
        .allow_all()
        .build(&t)?
        .authorize()?;
    println!("authorize(read, file1): ALLOWED (full chain verified)");

    // 5b. negative authorization: write must be denied by the attenuation check
    let t2 = Biscuit::from(&sealed, root.public())?;
    let denied = AuthorizerBuilder::new()
        .fact("resource(\"file1\")")?
        .fact("operation(\"write\")")?
        .allow_all()
        .build(&t2)?
        .authorize();
    match denied {
        Err(e) => println!("authorize(write, file1): correctly DENIED ({e})"),
        Ok(_) => panic!("write should be denied by the attenuation check"),
    }

    // 6. tamper a byte near the end (signature region) -> must be rejected
    let mut bad = sealed.clone();
    let idx = bad.len() - 8;
    bad[idx] ^= 0xFF;
    match Biscuit::from(&bad, root.public()) {
        Err(e) => println!("tampered token: correctly REJECTED ({e})"),
        Ok(_) => panic!("a tampered token must be rejected"),
    }

    // extended (3-hop) chain must also verify end to end
    let te = Biscuit::from(&sealed_ext, root.public())?;
    AuthorizerBuilder::new()
        .fact("resource(\"file1\")")?
        .fact("operation(\"read\")")?
        .allow_all()
        .build(&te)?
        .authorize()?;
    println!("3-hop unsealed->append->seal round trip: OK");

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    run(Algorithm::Ed25519, "classical baseline")?;
    run(Algorithm::Mldsa44, "post-quantum ML-DSA-44")?;
    println!("\nALL END-TO-END CHECKS PASSED");
    Ok(())
}
