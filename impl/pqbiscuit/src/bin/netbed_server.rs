//! E-N network authorization server.
//!
//! Minimal dependency-free HTTP/1.1 server that verifies a post-quantum Biscuit
//! capability token on every request. One TCP connection is handled per thread
//! and HTTP keep-alive is supported (multiple requests per connection).
//!
//!   GET /authz/<profile> HTTP/1.1
//!   Authorization: Bearer <base64url sealed token>
//!   X-Seq: <client request sequence number>
//!
//! On each request the server runs the production path: whole-chain signature
//! verification (`Biscuit::from` with the provisioned root public key) followed
//! by the Datalog authorizer, and echoes the on-path verification cost in the
//! `X-Verify-Ns` response header (and the sequence in `X-Seq`). 200 =
//! authorized, 403 = malformed/unauthorized, 404 = unknown profile.
//!
//! Run (inside the server network namespace):
//!   cargo run --release --bin netbed_server -- --addr 10.99.0.1:8080 \
//!       --keys ../../experiments/netbed/rootkeys

#[path = "netbed/common.rs"]
mod common;
use common::*;

use biscuit_auth::{Biscuit, PublicKey};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

fn load_keys(keys_dir: &str) -> HashMap<String, PublicKey> {
    let mut map = HashMap::new();
    for p in profiles() {
        map.insert(p.name.to_string(), load_root_key(keys_dir, p.name));
    }
    map
}

fn read_request(reader: &mut BufReader<TcpStream>) -> std::io::Result<Option<Request>> {
    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    if n == 0 {
        return Ok(None); // connection closed
    }
    let mut parts = line.trim_end().split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("HTTP/1.0").to_string();

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_length = 0usize;
    loop {
        let mut h = String::new();
        let hn = reader.read_line(&mut h)?;
        if hn == 0 {
            break;
        }
        let h = h.trim_end_matches(|c| c == '\r' || c == '\n');
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            let k = k.trim().to_lowercase();
            let v = v.trim().to_string();
            if k == "content-length" {
                content_length = v.parse().unwrap_or(0);
            }
            headers.push((k, v));
        }
    }
    if content_length > 0 {
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body)?;
    }
    Ok(Some(Request { method, path, version, headers }))
}

struct Request {
    method: String,
    path: String,
    version: String,
    headers: Vec<(String, String)>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
    fn wants_close(&self) -> bool {
        if let Some(c) = self.header("connection") {
            let c = c.to_lowercase();
            if c.contains("close") {
                return true;
            }
            if c.contains("keep-alive") {
                return false;
            }
        }
        self.version == "HTTP/1.0"
    }
}

/// Diagnostic dump for an unexpected 403: records the failure class and the
/// exact bearer token received so it can be diffed against the on-disk token
/// (truncation / splicing / corruption / wrong token). Fires only on a 403.
fn diag403(peer: &str, profile: &str, seq: &str, b64: Option<&str>, why: &str, err: &str) {
    let len = b64.map(str::len).unwrap_or(0);
    eprintln!("[403DIAG] peer={peer} profile={profile} seq={seq} why={why} len={len} err={err}");
    if let Some(b) = b64 {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true).append(true).open("/tmp/nbsrv_diag.b64")
        {
            let _ = writeln!(f, "### profile={profile} seq={seq} why={why} len={}\n{}", b.len(), b);
        }
    }
}

fn handle(stream: TcpStream, keys: Arc<HashMap<String, PublicKey>>) {
    let _ = stream.set_nodelay(true);
    let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".to_string());
    let writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);
    let mut out = BufWriter::new(writer);

    loop {
        let req = match read_request(&mut reader) {
            Ok(Some(r)) => r,
            Ok(None) => break,
            Err(_) => break,
        };

        let seq = req.header("x-seq").unwrap_or("0").to_string();
        let close = req.wants_close();

        let profile = req
            .path
            .strip_prefix("/authz/")
            .map(|s| s.split('?').next().unwrap_or(s).to_string());

        let t = Instant::now();
        let (status, reason) = match (req.method.as_str(), profile.as_deref()) {
            ("GET" | "POST", Some(profile)) => {
                let bearer = req
                    .header("authorization")
                    .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")))
                    .map(|s| s.trim().to_string());
                match (keys.get(profile), bearer) {
                    (Some(pk), Some(b64)) => match b64url_decode(&b64) {
                        Ok(raw) => match Biscuit::from(raw.as_slice(), pk) {
                            Ok(parsed) => {
                                if authorize_read(&parsed) {
                                    (200u16, "OK")
                                } else {
                                    diag403(&peer, profile, &seq, Some(&b64), "authorize_false", "");
                                    (403u16, "Forbidden")
                                }
                            }
                            Err(e) => {
                                diag403(&peer, profile, &seq, Some(&b64), "biscuit_from", &e.to_string());
                                (403u16, "Forbidden")
                            }
                        },
                        Err(e) => {
                            diag403(&peer, profile, &seq, Some(&b64), "b64_decode", &e.to_string());
                            (403u16, "Forbidden")
                        }
                    },
                    (None, _) => (404u16, "Not Found"),
                    (_, None) => {
                        diag403(&peer, profile, &seq, None, "no_bearer", "");
                        (403u16, "Forbidden")
                    }
                }
            }
            _ => (400u16, "Bad Request"),
        };
        let verify_ns = t.elapsed().as_nanos();
        let body: String = if status == 200 { "ok".to_string() } else { reason.to_lowercase() };
        let conn = if close { "close" } else { "keep-alive" };

        let resp = format!(
            "HTTP/1.1 {status} {reason}\r\n\
             Content-Type: text/plain\r\n\
             Content-Length: {}\r\n\
             X-Seq: {seq}\r\n\
             X-Verify-Ns: {verify_ns}\r\n\
             Connection: {conn}\r\n\r\n{}",
            body.len(),
            body
        );
        if out.write_all(resp.as_bytes()).is_err() {
            break;
        }
        if out.flush().is_err() {
            break;
        }
        if close {
            break;
        }
    }
}

fn main() {
    let mut addr = "0.0.0.0:8080".to_string();
    let mut keys_dir = format!("{OUT_DIR}/{KEY_SUBDIR}");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--addr" => addr = args.next().expect("value"),
            "--keys" => keys_dir = args.next().expect("value"),
            other => panic!("unknown arg {other}"),
        }
    }

    let keys = Arc::new(load_keys(&keys_dir));
    eprintln!("netbed_server: loaded {} root keys from {keys_dir}", keys.len());
    let listener = TcpListener::bind(&addr).expect("bind");
    eprintln!("netbed_server: listening on {addr}");

    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            let keys = Arc::clone(&keys);
            thread::spawn(move || handle(stream, keys));
        }
    }
}
