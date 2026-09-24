//! Shared helpers for the network-layer testbed bins (netbed_gen/server/client).
//!
//! This module is never compiled as its own binary (it lives under
//! src/bin/netbed/, which Cargo does not auto-discover); each netbed_*.rs bin
//! pulls it in with `#[path = "netbed/common.rs"] mod common;`.
#![allow(dead_code)]

use biscuit_auth::builder_ext::AuthorizerExt;
use biscuit_auth::{
    Algorithm, AuthorizerBuilder, AuthorizerLimits, Biscuit, BlockBuilder, KeyPair, PublicKey,
};
use std::fs;
use std::path::Path;
use std::time::Duration;

/// Relative to the crate root (impl/pqbiscuit), matching the other e5* bins.
pub const OUT_DIR: &str = "../../experiments/netbed";
pub const TOKEN_SUBDIR: &str = "tokens";
pub const KEY_SUBDIR: &str = "rootkeys";

pub const NS: [usize; 4] = [1, 5, 10, 20];

#[derive(Clone, Copy)]
pub struct Profile {
    pub name: &'static str,
    pub family: &'static str,
    pub root: &'static str,
    /// None => uniform/hybrid (every hop uses `root`); Some(b) => mixed chain.
    pub att: Option<&'static str>,
}

pub fn profiles() -> Vec<Profile> {
    vec![
        Profile { name: "ed25519", family: "classic", root: "ed25519", att: None },
        Profile { name: "mldsa44", family: "uniform", root: "mldsa44", att: None },
        Profile { name: "mldsa65", family: "uniform", root: "mldsa65", att: None },
        Profile { name: "mldsa87", family: "uniform", root: "mldsa87", att: None },
        Profile { name: "fndsa512", family: "uniform", root: "fndsa512", att: None },
        Profile { name: "fndsa1024", family: "uniform", root: "fndsa1024", att: None },
        Profile { name: "slhdsa128s", family: "uniform", root: "slhdsa128s", att: None },
        Profile { name: "slhdsa128f", family: "uniform", root: "slhdsa128f", att: None },
        Profile { name: "slhdsa256s", family: "uniform", root: "slhdsa256s", att: None },
        Profile { name: "slhdsa256f", family: "uniform", root: "slhdsa256f", att: None },
        Profile { name: "hyb-ed-mldsa44", family: "hybrid", root: "hybrid-ed-mldsa44", att: None },
        Profile { name: "hyb-ed-fndsa512", family: "hybrid", root: "hybrid-ed-fndsa512", att: None },
        Profile { name: "mix-mldsa87-fndsa512", family: "mixed", root: "mldsa87", att: Some("fndsa512") },
        Profile { name: "mix-slh256s-fndsa512", family: "mixed", root: "slhdsa256s", att: Some("fndsa512") },
        Profile { name: "mix-mldsa87-mldsa44", family: "mixed", root: "mldsa87", att: Some("mldsa44") },
    ]
}

pub fn find_profile(name: &str) -> Profile {
    *profiles().iter().find(|p| p.name == name)
        .unwrap_or_else(|| panic!("unknown profile {name}"))
}

pub fn parse_alg(s: &str) -> Algorithm {
    match s {
        "ed25519" => Algorithm::Ed25519,
        "mldsa44" => Algorithm::Mldsa44,
        "mldsa65" => Algorithm::Mldsa65,
        "mldsa87" => Algorithm::Mldsa87,
        "fndsa512" => Algorithm::Fndsa512,
        "fndsa1024" => Algorithm::Fndsa1024,
        "slhdsa128s" => Algorithm::Slhdsa128s,
        "slhdsa128f" => Algorithm::Slhdsa128f,
        "slhdsa256s" => Algorithm::Slhdsa256s,
        "slhdsa256f" => Algorithm::Slhdsa256f,
        "hybrid-ed-mldsa44" => Algorithm::HybridEdMldsa44,
        "hybrid-ed-fndsa512" => Algorithm::HybridEdFndsa512,
        other => panic!("unknown algorithm {other}"),
    }
}

fn hop_block() -> BlockBuilder {
    BlockBuilder::new()
        .check("check if operation(\"read\")")
        .expect("valid attenuation check")
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

/// Build the authority block plus `n` attenuation blocks under a fixed,
/// caller-supplied root key. For uniform/hybrid profiles every hop uses the
/// root algorithm; for mixed profiles the first hop installs the lighter
/// `att` key, which then signs every subsequent hop (mirrors e55_mixed.rs).
pub fn build_chain(root: &KeyPair, profile: Profile, n: usize) -> Biscuit {
    let mut token = authority(root);
    let hop_alg = profile
        .att
        .map(parse_alg)
        .unwrap_or_else(|| parse_alg(profile.root));
    for _ in 0..n {
        let kp = KeyPair::new_with_algorithm(hop_alg);
        token = token.append_with_keypair(&kp, hop_block()).expect("append hop");
    }
    token
}

/// Mint a fresh root and build a chain for a profile (convenience wrapper).
pub fn build_token(profile: Profile, n: usize) -> (KeyPair, Biscuit) {
    let root = KeyPair::new_with_algorithm(parse_alg(profile.root));
    let token = build_chain(&root, profile, n);
    (root, token)
}

/// Production authorization load, identical to the e55 micro-benchmark.
///
/// The crate's default `RunLimits` cap Datalog evaluation at a 1 ms *wall-clock*
/// budget (an anti-DoS default). Under CPU contention (a single pinned server
/// core serving many concurrent connections), the evaluator is descheduled and
/// can cross 1 ms of elapsed time despite doing well under 1 ms of real work,
/// yielding a spurious `RunLimit::Timeout` and hence a false 403. We measure
/// signature-migration cost, not the authorizer's DoS budget, so we relax the
/// wall-clock limit to the value the crate itself uses in its test suite (10 s)
/// while leaving the deterministic fact/iteration caps at their defaults; the
/// authorization outcome is then purely a function of the (deterministic)
/// policy and is independent of OS scheduling.
pub fn authorize_read(parsed: &Biscuit) -> bool {
    AuthorizerBuilder::new()
        .fact("resource(\"file1\")")
        .unwrap()
        .fact("operation(\"read\")")
        .unwrap()
        .allow_all()
        .set_limits(AuthorizerLimits {
            max_facts: 1000,
            max_iterations: 100,
            max_time: Duration::from_secs(10),
        })
        .build(parsed)
        .unwrap()
        .authorize()
        .is_ok()
}

pub fn seal_token(token: Biscuit) -> Vec<u8> {
    token.seal().expect("seal").to_vec().expect("sealed serialize")
}

pub fn root_key_path(profile_name: &str) -> String {
    format!("{OUT_DIR}/{KEY_SUBDIR}/{profile_name}.pub")
}
pub fn token_path(profile_name: &str, n: usize) -> String {
    format!("{OUT_DIR}/{TOKEN_SUBDIR}/{profile_name}_n{n}.tok")
}

pub fn ensure_dirs() {
    fs::create_dir_all(format!("{OUT_DIR}/{TOKEN_SUBDIR}")).unwrap();
    fs::create_dir_all(format!("{OUT_DIR}/{KEY_SUBDIR}")).unwrap();
    fs::create_dir_all("../../experiments/data").unwrap();
}

pub fn load_root_key(keys_dir: &str, profile_name: &str) -> PublicKey {
    let p = Path::new(keys_dir).join(format!("{profile_name}.pub"));
    let s = fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
    s.trim().parse::<PublicKey>().expect("parse root public key")
}

pub fn load_token_b64(tokens_dir: &str, profile_name: &str, n: usize) -> String {
    let p = Path::new(tokens_dir).join(format!("{profile_name}_n{n}.tok"));
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display())).trim().to_string()
}

// ---------------- base64url (no padding), dependency-free ----------------

const B64: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn b64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 4 + 2) / 3);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[((triple >> 18) & 63) as usize] as char);
        out.push(B64[((triple >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64[((triple >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64[(triple & 63) as usize] as char);
        }
    }
    out
}

pub fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    let val = |c: u8| -> Result<u32, String> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'-' => Ok(62),
            b'_' => Ok(63),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("bad b64 char {c}")),
        }
    };
    let bytes: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut buf = [0u32; 4];
        let mut pad = 0;
        for i in 0..4 {
            if i < chunk.len() {
                buf[i] = val(chunk[i])?;
            } else {
                buf[i] = 0;
                pad += 1;
            }
        }
        let triple = (buf[0] << 18) | (buf[1] << 12) | (buf[2] << 6) | buf[3];
        out.push((triple >> 16) as u8);
        if pad < 2 {
            out.push((triple >> 8) as u8);
        }
        if pad < 1 {
            out.push(triple as u8);
        }
    }
    Ok(out)
}
