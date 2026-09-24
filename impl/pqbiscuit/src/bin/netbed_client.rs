//! E-N network load generator (latency and throughput subcommands).
//!
//! latency:    single outstanding request at a time (no self-induced queueing),
//!             `--mode new` opens a fresh TCP connection per request (timer
//!             includes the handshake), `--mode ka` reuses one keep-alive
//!             connection. Writes one row per request to net_latency.csv.
//! throughput: `--conc` persistent keep-alive connections run for `--duration`
//!             seconds after a warm-up and a start barrier; writes one aggregate
//!             row (rps + P50/P95/P99) to net_throughput.csv.
//!
//! Examples (from impl/pqbiscuit, inside the client namespace):
//!   cargo run --release --bin netbed_client -- latency \
//!     --server 10.99.0.1:8080 --tokens ../../experiments/netbed/tokens \
//!     --profile fndsa512 --n 20 --mode ka --samples 1000 --rtt 20 --loss 0
//!   cargo run --release --bin netbed_client -- throughput \
//!     --server 10.99.0.1:8080 --tokens ../../experiments/netbed/tokens \
//!     --profile fndsa512 --n 20 --conc 8 --duration 15 --rep 1 --rtt 20

#[path = "netbed/common.rs"]
mod common;
use common::*;

use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

struct Conn {
    reader: BufReader<TcpStream>,
    writer: BufWriter<TcpStream>,
}

impl Conn {
    fn connect(addr: &str) -> std::io::Result<Conn> {
        let s = TcpStream::connect(addr)?;
        s.set_nodelay(true)?;
        let w = s.try_clone()?;
        Ok(Conn { reader: BufReader::new(s), writer: BufWriter::new(w) })
    }

    /// Connect with bounded retries; under injected loss a SYN or an early
    /// segment may be dropped by netem. Never panics on a transient failure.
    fn connect_retry(addr: &str, tries: u32) -> std::io::Result<Conn> {
        let mut last = None;
        for i in 0..tries {
            match Conn::connect(addr) {
                Ok(c) => return Ok(c),
                Err(e) => {
                    last = Some(e);
                    if i + 1 < tries {
                        thread::sleep(Duration::from_millis(200));
                    }
                }
            }
        }
        Err(last.unwrap())
    }

    /// One HTTP request; returns (http_status, server verify time in ns).
    fn request(&mut self, profile: &str, b64: &str, seq: u64, close: bool)
        -> std::io::Result<(u16, u128)>
    {
        let conn = if close { "close" } else { "keep-alive" };
        let req = format!(
            "GET /authz/{profile} HTTP/1.1\r\n\
             Host: netbed\r\n\
             Authorization: Bearer {b64}\r\n\
             X-Seq: {seq}\r\n\
             Connection: {conn}\r\n\r\n"
        );
        self.writer.write_all(req.as_bytes())?;
        self.writer.flush()?;

        let mut line = String::new();
        self.reader.read_line(&mut line)?;
        let status = line.split_whitespace().nth(1).and_then(|x| x.parse().ok()).unwrap_or(0);
        let mut clen = 0usize;
        let mut verify_ns = 0u128;
        loop {
            let mut h = String::new();
            let n = self.reader.read_line(&mut h)?;
            if n == 0 {
                break;
            }
            let h = h.trim_end_matches(['\r', '\n']);
            if h.is_empty() {
                break;
            }
            if let Some((k, v)) = h.split_once(':') {
                let k = k.trim().to_lowercase();
                let v = v.trim();
                if k == "content-length" {
                    clen = v.parse().unwrap_or(0);
                } else if k == "x-verify-ns" {
                    verify_ns = v.parse().unwrap_or(0);
                }
            }
        }
        if clen > 0 {
            let mut body = vec![0u8; clen];
            self.reader.read_exact(&mut body)?;
        }
        Ok((status, verify_ns))
    }
}

fn percentile(sorted: &[u128], q: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((q / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn append_csv(path: &str, header: &str, line: &str) {
    let exists = std::path::Path::new(path).exists();
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path).unwrap();
    if !exists {
        writeln!(f, "{header}").unwrap();
    }
    writeln!(f, "{line}").unwrap();
}

struct Opts {
    m: std::collections::HashMap<String, String>,
}
impl Opts {
    fn get(&self, k: &str) -> String { self.m.get(k).cloned().unwrap_or_default() }
}
fn parse_args(a: &[String]) -> Opts {
    let mut m = std::collections::HashMap::new();
    let mut i = 0;
    while i < a.len() {
        if a[i].starts_with("--") {
            let key = a[i].trim_start_matches("--").to_string();
            if i + 1 < a.len() && !a[i + 1].starts_with("--") {
                m.insert(key, a[i + 1].clone());
                i += 2;
            } else {
                m.insert(key, "true".to_string());
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    Opts { m }
}

// New-connection latency loop: a fresh TCP connection per request, so the timer
// includes the three-way handshake. (keep-alive is handled by run_latency_ka.)
fn run_latency(o: &Opts) {
    let server = o.get("server");
    let tokens = o.get("tokens");
    let profile = o.get("profile");
    let n: usize = o.get("n").parse().unwrap();
    let samples: u64 = o.get("samples").parse().unwrap_or(400);
    let rtt = o.get("rtt");
    let loss = o.get("loss");
    let rate = if o.get("rate").is_empty() { "unlim".to_string() } else { o.get("rate") };
    let out = if o.get("out").is_empty() {
        "../../experiments/data/net_latency.csv".to_string()
    } else { o.get("out") };

    let exp = { let e = o.get("exp"); if e.is_empty() { "latency".to_string() } else { e } };
    let p = find_profile(&profile);
    let att = p.att.unwrap_or(p.root);
    let b64 = load_token_b64(&tokens, &profile, n);

    if o.get("nowarm") != "true" {
        for _ in 0..10 {
            if let Ok(mut c) = Conn::connect(&server) {
                let _ = c.request(&profile, &b64, 0, true);
            }
        }
    }

    let header = "exp,family,profile,root,att,n,mode,rtt_ms,loss_pct,rate,seq,total_ns,verify_ns,status";
    let mut ok = 0u64;
    for seq in 1..=samples {
        let t0 = Instant::now();
        // A dropped SYN/segment under netem must be recorded as a failed sample
        // (status=0), not abort the whole multi-hour stage.
        let (status, verify_ns) = match Conn::connect_retry(&server, 3) {
            Ok(mut conn) => match conn.request(&profile, &b64, seq, true) {
                Ok(sv) => sv,
                Err(_) => (0u16, 0u128),
            },
            Err(_) => (0u16, 0u128),
        };
        let total_ns = t0.elapsed().as_nanos();
        if status == 200 { ok += 1; }
        append_csv(&out, header, &format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            exp, p.family, profile, p.root, att, n, "new", rtt, loss, rate,
            seq, total_ns, verify_ns, status
        ));
    }
    eprintln!("{exp}[{profile} n={n} new RTT={rtt} loss={loss} {rate}] {ok}/{samples} 200-OK");
}

// Dedicated keep-alive latency loop (single persistent connection).
fn run_latency_ka(o: &Opts, out: &str, header: &str) {
    let server = o.get("server");
    let tokens = o.get("tokens");
    let profile = o.get("profile");
    let n: usize = o.get("n").parse().unwrap();
    let samples: u64 = o.get("samples").parse().unwrap_or(1000);
    let rtt = o.get("rtt");
    let loss = o.get("loss");
    let rate = if o.get("rate").is_empty() { "unlim".to_string() } else { o.get("rate") };
    let exp = { let e = o.get("exp"); if e.is_empty() { "latency".to_string() } else { e } };
    let p = find_profile(&profile);
    let att = p.att.unwrap_or(p.root);
    let b64 = load_token_b64(&tokens, &profile, n);

    let mut conn = match Conn::connect_retry(&server, 5) {
        Ok(c) => c,
        Err(e) => { eprintln!("ka connect failed after retries: {e}"); return; }
    };
    if o.get("nowarm") != "true" {
        for _ in 0..30 {
            if conn.request(&profile, &b64, 0, false).is_err() {
                if let Ok(c) = Conn::connect_retry(&server, 5) { conn = c; }
            }
        }
    }
    let mut ok = 0u64;
    for seq in 1..=samples {
        let t0 = Instant::now();
        let mut sv = conn.request(&profile, &b64, seq, false);
        if sv.is_err() {
            // the persistent connection was reset; rebuild it once, then record
            // this sample as failed (status=0) if it still does not succeed.
            if let Ok(c) = Conn::connect_retry(&server, 3) {
                conn = c;
                sv = conn.request(&profile, &b64, seq, false);
            }
        }
        let (status, verify_ns) = sv.unwrap_or((0u16, 0u128));
        let total_ns = t0.elapsed().as_nanos();
        if status == 200 { ok += 1; }
        append_csv(out, header, &format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            exp, p.family, profile, p.root, att, n, "ka", rtt, loss, rate,
            seq, total_ns, verify_ns, status
        ));
    }
    eprintln!("{exp}[{profile} n={n} ka RTT={rtt} loss={loss} {rate}] {ok}/{samples} 200-OK");
}

fn run_throughput(o: &Opts) {
    let server = Arc::new(o.get("server"));
    let tokens = o.get("tokens");
    let profile = Arc::new(o.get("profile"));
    let n: usize = o.get("n").parse().unwrap();
    let conc: usize = o.get("conc").parse().unwrap_or(1);
    let duration: u64 = o.get("duration").parse().unwrap_or(15);
    let rep = o.get("rep");
    let rtt = o.get("rtt");
    let out = if o.get("out").is_empty() {
        "../../experiments/data/net_throughput.csv".to_string()
    } else { o.get("out") };

    let p = find_profile(&profile);
    let b64 = Arc::new(load_token_b64(&tokens, &profile, n));
    let barrier = Arc::new(Barrier::new(conc));
    let mut handles = Vec::new();

    for _ in 0..conc {
        let server = Arc::clone(&server);
        let profile = Arc::clone(&profile);
        let b64 = Arc::clone(&b64);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let mut conn = Conn::connect_retry(&server, 10).ok();
            for _ in 0..100 {
                let need_reconnect = match conn {
                    Some(ref mut c) => c.request(&profile, &b64, 0, false).is_err(),
                    None => true,
                };
                if need_reconnect {
                    conn = Conn::connect_retry(&server, 10).ok();
                }
            }
            barrier.wait();
            let start = Instant::now();
            let deadline = start + Duration::from_secs(duration);
            let mut completed = 0u64;
            let mut failed = 0u64;
            let mut samples: Vec<(u128, u128)> = Vec::new();
            let mut seq = 0u64;
            while Instant::now() < deadline {
                seq += 1;
                let t0 = Instant::now();
                if conn.is_none() {
                    conn = Conn::connect_retry(&server, 3).ok();
                }
                let res = match conn {
                    Some(ref mut c) => c.request(&profile, &b64, seq, false),
                    None => Err(std::io::Error::new(
                        std::io::ErrorKind::NotConnected, "no connection")),
                };
                match res {
                    Ok((200, v)) => {
                        completed += 1;
                        // bounded reservoir-free stride sampling (~2000/thread)
                        if completed % 5 == 0 || samples.len() < 2000 {
                            samples.push((t0.elapsed().as_nanos(), v));
                        }
                    }
                    // non-200 or I/O error: count once, then rebuild the
                    // connection on the next iteration instead of failing fast.
                    _ => {
                        failed += 1;
                        conn = None;
                    },
                }
            }
            (completed, failed, samples)
        }));
    }

    let mut completed = 0u64;
    let mut failed = 0u64;
    let mut lat: Vec<u128> = Vec::new();
    let mut ver: Vec<u128> = Vec::new();
    for h in handles {
        let (c, f, s) = h.join().unwrap();
        completed += c;
        failed += f;
        for (l, v) in s {
            lat.push(l);
            ver.push(v);
        }
    }
    lat.sort_unstable();
    let p50 = percentile(&lat, 50.0);
    let p95 = percentile(&lat, 95.0);
    let p99 = percentile(&lat, 99.0);
    let vmean = if ver.is_empty() { 0 } else { ver.iter().sum::<u128>() / ver.len() as u128 };
    let rps = completed as f64 / duration as f64;

    let header = "profile,family,n,rtt_ms,conc,rep,duration_s,completed,failed,rps,p50_ns,p95_ns,p99_ns,verify_mean_ns";
    append_csv(&out, header, &format!(
        "{},{},{},{},{},{},{},{},{},{:.2},{},{},{},{}",
        profile, p.family, n, rtt, conc, rep, duration, completed, failed,
        rps, p50, p95, p99, vmean
    ));
    eprintln!(
        "throughput[{profile} n={n} c={conc} RTT={rtt} rep={rep}] {completed} ok / {failed} fail in {duration}s = {rps:.1} req/s; P50={p50} P95={p95} P99={p99} ns"
    );
}

fn main() {
    let all: Vec<String> = std::env::args().collect();
    let sub = all.get(1).cloned().unwrap_or_default();
    let o = parse_args(&all[2..]);
    match sub.as_str() {
        "latency" => {
            let mode = o.get("mode");
            let out = if o.get("out").is_empty() {
                "../../experiments/data/net_latency.csv".to_string()
            } else { o.get("out") };
            let header = "exp,family,profile,root,att,n,mode,rtt_ms,loss_pct,rate,seq,total_ns,verify_ns,status";
            if mode == "ka" {
                run_latency_ka(&o, &out, header);
            } else {
                run_latency(&o);
            }
        }
        "throughput" => run_throughput(&o),
        other => panic!("unknown subcommand {other}; use `latency` or `throughput`"),
    }
}
