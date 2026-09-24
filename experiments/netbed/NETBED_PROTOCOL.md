# Network-Layer Measurement Protocol — Post-Quantum Biscuit Capability Tokens (E-N series)

Status: **frozen before implementation** (theory/metric definitions first, code second).
Scope: measure the deployability and performance impact of post-quantum
signature schemes on **offline-attenuating Biscuit capability tokens carried in
real network authorization transactions**, on a fully software, local,
reproducible testbed (no hardware, no cloud, no real machines).

This protocol is the network-layer companion to the cryptographic
micro-benchmarks (E5/E55/E56/E6). The micro-benchmarks isolate per-operation
CPU time and token bytes; the E-N series place the **same sealed tokens** inside
actual TCP/HTTP request–response transactions under controlled RTT, loss and
bandwidth, and measure end-to-end latency, tail latency, throughput,
segmentation/retransmission, and footprint.

---

## 1. Research questions

- **RQ-N1 (latency & amortization).** For each signature family / chain
  construction / attenuation length, how does end-to-end authorization latency
  grow with round-trip time? At what RTT does the on-path verification cost
  become negligible relative to network delay (the amortization crossover)?
- **RQ-N2 (segmentation & loss → tail latency).** Large tokens span multiple
  TCP segments. How does independent packet loss amplify P95/P99 latency as a
  function of token size? Do hybrid and strong-root/light-hop (mixed)
  constructions keep the request inside the Linux initial congestion window and
  avoid that amplification?
- **RQ-N3 (server throughput).** What sustained authorized-request rate
  (req/s) does a verifier achieve at concurrency 1/8/32, and where is the
  bottleneck (verification CPU vs. network)?
- **RQ-N4 (constrained links).** Under low bandwidth (broadband-IoT / LTE-M /
  NB-IoT-like rates), how do token bytes translate into transfer time, and how
  much does byte reduction (mixed/hybrid) save end-to-end?
- **RQ-N5 (deployment footprint).** Peak resident memory and verifier binary
  size for each backend.

---

## 2. System model and transaction abstraction

A principal holds a **sealed** Biscuit token comprising one authority block,
`n ≥ 1` attenuation blocks (each adding a Datalog check and a fresh next-key),
and a final seal signature. Every request to a protected resource carries the
token in the application-layer header

```
Authorization: Bearer <base64url(sealed token bytes)>
```

over HTTP/1.1 over TCP. The server is provisioned out-of-band with the root
public key, and on each request performs exactly the production verification
path:

1. `Biscuit::from(token_bytes, root_public_key)` — parse and verify **every**
   block signature and the seal over the whole chain;
2. build a Datalog authorizer with ambient facts `resource("file1")`,
   `operation("read")` and `allow_all`, then `.authorize()` (the same
   authorization load used in the E55 micro-benchmark).

It returns `200` on success and `403` on failure. A one-byte tamper and a
wrong-root token are additionally checked to confirm the network path still
enforces authentication.

**Scope boundary (stated, not hidden).** We migrate the *capability-token
signature scheme*, not the TLS handshake. The main experiments therefore use
HTTP/1.1 over TCP with the token in an application header. RTT, segmentation,
loss and bandwidth act on the token bytes identically whether the stream is
plaintext or runs inside a TLS tunnel: TLS adds a constant per-record framing
and handshake that is independent of the token signature algorithm, so the
*relative* comparison across schemes is unchanged. The segment arithmetic maps
directly to TLS-record fragmentation (a >16 KB record is fragmented, as in
Paul et al., AsiaCCS'22). TLS-handshake cost is out of scope and is named in
the paper's limitations.

**Connection modes.**
- `newconn`: a fresh TCP connection per request (three-way handshake then the
  request/response); models cold/short-lived clients.
- `ka`: one persistent keep-alive connection carrying many requests, each
  still bearing the token; models long-lived service-to-service sessions.

---

## 3. Testbed topology and control

Two Linux network namespaces connected by a veth pair:

```
   nbC (client) 10.99.0.2/24            10.99.0.1/24 (server) nbS
        vC ◄────────── veth pair ──────────► vS
              tc netem/tbf on each veth
```

- MTU 1500, TCP payload MSS = 1460 (verified at run time; recorded).
- Propagation: `netem delay d` **symmetrically** on vC and vS with `d = τ/2`,
  so the measured baseline RTT equals the target `τ ∈ {0,1,5,20,50,100,200}` ms.
- Loss: independent Bernoulli `p ∈ {0,1,3,5}%` applied on the **client veth
  egress only**, so each request segment is dropped with probability p on one
  direction with a single, well-defined loss point (avoids the ambiguity of
  composing two loss stages). `netem` uses independent, non-correlated loss.
- Bandwidth (RQ-N4): `tbf rate B` symmetric, `B ∈ {1mbit, 46kbit}` with a
  200 ms latency bucket; unlimited otherwise.
- Every network condition is **re-applied and calibrated immediately before
  its measurement** (qdisc state is never assumed to persist from a previous
  stage — an earlier caching bug that skipped re-applying the qdisc let E-N3
  run under a stale rtt20/loss5 condition and was fixed): the orchestrator
  always rebuilds the qdisc, then pings to record empirical RTT min/avg/max and
  loss to `net_calibrate.csv`, tagged with the stage. At loss 0 it sends 20
  pings at 50 ms intervals for RTT; for any lossy condition it sends 100 pings
  at 20 ms intervals so the empirical loss estimate is not dominated by
  sampling noise (20 pings at p=5% observe zero loss with probability
  0.95^20≈0.36). Analysis uses the *target* τ/p as the independent variable and
  reports the empirical calibrated value alongside.
- Determinism: release build (`opt-level=3`, thin LTO, codegen-units=1).
  Latency stages pin the server to one isolated core (core 10) and the client
  to a separate single core (core 6) via `taskset`; the throughput stage pins
  the server to cores 2–5 and the client to cores 6–9 so neither endpoint is
  artificially single-threaded. Warm-up requests run first, except E-N5 which
  uses `--nowarm` with a single request so the capture contains exactly one
  transaction (an earlier run that kept the 10 warm-up connections counted
  11 requests per capture). No other load. Kernel, CPU, cargo/rustc versions
  and MSS are recorded to `net_meta.txt`.
- All `ip netns`/`tc` operations run as root; the two Rust binaries run inside
  the namespaces. The testbed is created/destroyed by scripts
  (`netbed_up.sh`, `netbed_set.sh`, `netbed_down.sh`) for one-command
  reproduction.

---

## 4. Chain profiles under test

Uniform chains use one algorithm for the root and every hop; hybrid chains use
a labelled Ed∘PQ nested signature for every block; mixed chains use a
conservative root algorithm A that signs the authority and block 1, then a
lighter algorithm B for blocks 2..n and the seal (root cost constant, per-hop
cost follows B).

| family  | profile            | root alg      | attenuation alg | n tested        |
|---------|--------------------|---------------|-----------------|-----------------|
| classic | ed25519            | Ed25519       | Ed25519         | 1,5,10,20       |
| uniform | mldsa44            | ML-DSA-44     | ML-DSA-44       | 1,5,10,20       |
| uniform | mldsa65            | ML-DSA-65     | ML-DSA-65       | 1,5,10,20       |
| uniform | mldsa87            | ML-DSA-87     | ML-DSA-87       | 1,5,10,20       |
| uniform | fndsa512           | FN-DSA-512    | FN-DSA-512      | 1,5,10,20       |
| uniform | fndsa1024          | FN-DSA-1024   | FN-DSA-1024     | 1,5,10,20       |
| uniform | slhdsa128s         | SLH-DSA-128s  | SLH-DSA-128s    | 1,5,10,20       |
| uniform | slhdsa128f         | SLH-DSA-128f  | SLH-DSA-128f    | 1,5,10,20       |
| uniform | slhdsa256s         | SLH-DSA-256s  | SLH-DSA-256s    | 1,5,10,20       |
| uniform | slhdsa256f         | SLH-DSA-256f  | SLH-DSA-256f    | 1,5,10,20       |
| hybrid  | hyb-ed-mldsa44     | Ed+ML-DSA-44  | Ed+ML-DSA-44    | 1,5,10,20       |
| hybrid  | hyb-ed-fndsa512    | Ed+FN-DSA-512 | Ed+FN-DSA-512   | 1,5,10,20       |
| mixed   | mix-mldsa87-fndsa512  | ML-DSA-87   | FN-DSA-512      | 1,5,10,20       |
| mixed   | mix-slh256s-fndsa512  | SLH-DSA-256s| FN-DSA-512      | 1,5,10,20       |
| mixed   | mix-mldsa87-mldsa44   | ML-DSA-87   | ML-DSA-44       | 1,5,10,20       |

Tokens for all profiles/n are **pre-generated offline once** and reused across
all network conditions (removes signing/key-generation noise from the network
path; the offline signing cost is already quantified by E5/E55/E6 and is
reported separately). The server receives only the root public key; the client
reads the sealed tokens.

---

## 5. Experiment matrix

- **E-N1 latency vs RTT (loss 0, unlimited bw):** all 15 profiles ×
  n{1,5,10,20} × τ{0,1,5,20,50,100,200} ms × mode{newconn, ka}. End-to-end
  latency distribution and server verification time.
- **E-N2 latency vs loss (τ=20 ms):** a size-stratified subset
  {ed25519, fndsa512, mldsa87, slhdsa128f, hyb-ed-fndsa512,
  mix-mldsa87-fndsa512} × n{1,10,20} × p{0,1,3,5}% × both modes; P50/P95/P99
  and measured TCP retransmissions.
- **E-N3 throughput:** keep-alive, concurrency c{1,8,32}, τ{0,1,20} ms,
  profiles {ed25519, mldsa44, mldsa87, fndsa512, fndsa1024, slhdsa128f,
  hyb-ed-fndsa512, mix-mldsa87-fndsa512} × n{1,20}; fixed 15 s windows, 3
  repetitions; report req/s and latency percentiles.
- **E-N4 constrained bandwidth:** B{1 mbit, 46 kbit} at τ=50 ms,
  {ed25519, fndsa512, mldsa87, slhdsa128f, hyb-ed-fndsa512,
  mix-mldsa87-fndsa512} × n{10,20}, ka; latency decomposed against S/B.
  Samples per point are 30 at 1 mbit and 20 at 46 kbit (a multi-hundred-KiB
  SLH token at 46 kbit takes tens of seconds per request, so the sample count
  is reduced while CI is still reported); the point is the serialization
  slope, not sub-ms precision.
- **E-N5 wire segmentation (deterministic + measured):** for every
  profile × n, request/response byte counts, predicted upstream/downstream
  segment counts, over-initial-cwnd indicator, and a **single warm-up-free
  (`--nowarm`) new-connection transaction** captured by `tcpdump` (loss 0,
  RTT≈2 ms), counting only data segments (`length ≥ 1`; SYN/ACK/FIN and pure
  ACKs have length 0 and are excluded) per direction.
- **E-N6 footprint:** verifier binary size (raw and `strip`ped) and peak RSS
  for representative backends, read as the kernel's high-water mark
  `VmHWM` from `/proc/<pid>/status` after a c=8, 12 s steady-load window
  (ed25519, fndsa512, slhdsa128f).

E-N1 is the full factorial; E-N2/E-N3/E-N4 stratify on representative
small/medium/large and recommended constructions to keep the high-RTT and
15-second runs tractable while covering every family and both deployment
recommendations (hybrid, strong-root/light-hop).

---

## 6. Metrics and formal definitions

### 6.1 End-to-end latency
For request *i*, the client measures wall-clock time on a monotonic clock.

- keep-alive: `L_i = t(complete response received) − t(request first byte sent)`.
- new connection: `L_i = t(complete response received) − t(TCP connect starts)`,
  so it includes the three-way handshake.

The server records per-request **full server processing time**
`t_srv,i = t(authorize returns) − t(Bearer token located in request)`; this
spans base64url decoding, protobuf parsing, `Biscuit::from` (whole-chain
signature + seal verification) and Datalog `.authorize()`, i.e. everything the
production verifier does on the wire bytes. Client and server rows are aligned
by a per-request sequence number echoed in an HTTP response header. This is
deliberately *not* the same clock as the cryptographic micro-benchmarks:
E56's `verify_chain` measures pure signature verification of an in-memory
chain, while E6's whole-chain verify is closer to but still excludes the
base64/parse step. The paper reports all three under distinct labels
(`t_srv` network, E6 whole-chain, E56 pure-verify) and cross-checks *ratios*
(scheme A over Ed25519) rather than absolute microseconds; the network
fn/ed ratio is therefore expected to exceed the E6 1.057× ratio because
parsing cost grows with token bytes.

For a sample of size m report mean, standard deviation, and percentiles
`P50, P95, P99` (nearest-rank / linear-interpolated quantile), plus a
bootstrap 95% confidence interval on P95 and P99 (10 000 resamples).

### 6.2 Latency model (predictions to be tested)
With one-way propagation `d = τ/2`, negligible loss, bandwidth not limiting,
and the request/response fitting in the initial congestion window:

- keep-alive: one request/response round-trip plus server work,
  `L_ka ≈ τ + t_srv + ε`.
- new connection: a three-way handshake (the request is piggy-backed on the
  final ACK) plus one request/response round-trip,
  `L_new ≈ 2τ + t_srv + ε`.

`ε` captures scheduling, segmentation and HTTP parsing and is measured at
τ=0. The new-connection model is **conditioned on the initial congestion
window** (§6.3): when `O_cwnd = 1`, slow start forces `k ≥ 1` additional
round-trips before the oversized request is fully in flight, giving
`L_new ≈ (2 + k)τ + t_srv + ε`. A pilot run already confirms this: an
FN-DSA-512 n=20 request (≈6 upstream segments, inside cwnd0 in segment count
but with the base64 token crossing the initial flight in bytes) measures
≈4τ at RTT=20 ms rather than the naive 2τ, i.e. one extra round-trip; the
exact k per profile/n is taken from E-N5 and fitted, not assumed. Keep-alive
requests are sent one at a time on an established connection and never pay
this slow-start penalty.

### 6.3 Segmentation and the initial congestion window
Let `S_up` be the total upstream request bytes (request line + headers +
Bearer token) and `MSS = 1460` the TCP payload. The number of upstream
full-sized data segments is
`N_up = ceil(S_up / MSS)`; the downstream response is tiny (`N_dn ≈ 1`).
Linux initialises the congestion window to `cwnd0 = 10` segments, i.e. about
`10·MSS ≈ 14 600` bytes. Define the over-window indicator
`O_cwnd = 1[ S_up > 10·MSS ]`.
When `O_cwnd = 1` and the window has not yet grown, the sender must wait for
ACKs (slow start), adding on the order of one or more RTTs before the full
token is delivered — a cost that small-token constructions avoid.

### 6.4 Loss and retransmission probability
Under independent Bernoulli segment loss with probability p and N data
segments that must all arrive, the probability that **at least one** segment is
lost (and therefore triggers a retransmission) is

 `P_loss(N,p) = 1 − (1 − p)^N`.

The expected number of lost segments is `E[R] = N·p`, and of retransmission
attempts per segment `p/(1−p)`, hence `E[retransmissions] = N·p/(1−p)`.
The measured retransmission count is taken from per-namespace kernel counters
(`TcpRetransSegs` via `nstat`/`netstat -s` delta) and corroborated by
`tcpdump`; tail-latency inflation under loss is measured rather than assumed
(RTO vs. fast retransmit is not modelled away).

### 6.5 Verification share and the amortization crossover
The fraction of end-to-end latency spent on server-side token processing is
`ρ(τ) = t_srv / L(τ)`.
Using the §6.2 models and ignoring ε:

- keep-alive: `ρ_ka(τ) = t_srv/(τ + t_srv)`, which equals 0.5 at `τ* = t_srv`;
- new connection (in-window): `ρ_new(τ) = t_srv/(2τ + t_srv)`, equal to 0.5 at
  `τ* = t_srv/2` (over-window new connections use the `(2+k)τ` denominator).

`τ*` is the amortization crossover: above it, network delay — not signature
verification — dominates. We report τ* per profile/n and overlay the measured
ρ curve on the prediction.

### 6.6 Throughput
With c concurrent keep-alive clients over a wall-clock window T completing
N_comp authorized requests, `X_c = N_comp / T` (req/s). Internal consistency is
checked against Little's law: `L · X ≈ c` (below saturation). The saturation
throughput `X_sat` identifies whether the verifier CPU or the network is the
binding constraint; at τ=0 the per-scheme single-connection rate must agree
with the inverse of the network `t_srv`, and its scheme ratios are
cross-checked against E6 whole-chain ratios (with the E56 pure-verify ratio
shown separately to expose the parse/decode component). Cross-validation only;
no new primitive is claimed.

### 6.7 Constrained-bandwidth transfer time
At rate B (bit/s), the size-induced serialisation delay is
`t_B = (S_up + S_dn)·8 / B`, added to the round-trip and server terms.
Measured latency minus (τ + t_srv) is regressed against wire bytes to confirm
the 1/B slope; byte savings from mixed/hybrid constructions translate
linearly on narrow links.

### 6.8 Footprint
Peak resident set size under a steady request load and the stripped verifier
binary size, per backend, in KiB/bytes.

---

## 7. Sampling and statistical protocol

- Warm-up: ≥20 completed transactions before timing at each condition
  (connection setup, branch prediction, allocator and verifier tables warm).
- E-N1/E-N2 latency: **1000** samples per point for ka and **400** for
  newconn at τ < 100 ms; at τ ≥ 100 ms use **400** (ka) / **200** (newconn) to
  bound wall-clock while keeping P99 stable (CI reported).
- E-N4 narrowband latency: **30** ka samples at 1 mbit, **20** at 46 kbit
  (serialization, not sub-ms variance, is the quantity of interest; CI still
  reported). E-N5 uses exactly **1** warm-up-free new-connection transaction
  per profile/n.
- E-N3 throughput: three independent 15 s windows per condition after a
  per-thread warm-up; report median and spread across the three runs.
- The same pre-generated token batch is reused for a profile across all
  conditions (controlled comparison); tokens are regenerated per profile/n but
  not per network condition.
- All clocks are monotonic (`Instant`, ns). The client measures end-to-end;
  the server measures t_srv (full handling, §6.1); sequence numbers align them.
- Failures/timeouts under loss are counted, not silently retried by the
  harness: the client uses normal OS TCP retransmission and records any
  transaction exceeding a generous deadline separately.
- **Authorizer wall-clock budget (spurious-403 guard, root-caused).**
  `biscuit_auth`'s default `RunLimits` cap Datalog evaluation at a **1 ms
  wall-clock** budget (an anti-DoS default). With the server pinned to one
  core, descheduling under concurrent connections can cross 1 ms of *elapsed*
  time on well under 1 ms of real work, so the evaluator returns
  `RunLimit::Timeout` and the server emits a false 403. Before the fix this was
  observed at 0.010% under serial load (only at RTT ≥ 20 ms, where
  per-connection threads briefly overlap) and 0.21% under 16-way concurrency;
  every captured token was byte-identical to the on-disk token and the failure
  class was `authorize_false` (never a decode/parse/signature error). The
  harness therefore sets `max_time = 10 s` (the value the crate itself uses in
  its test suite) in `authorize_read`, leaving the deterministic `max_facts`
  (1000) and `max_iterations` (100) caps at their defaults; outcomes are then
  a pure function of the deterministic policy, independent of OS scheduling.
  We measure signature-migration cost, not the authorizer's DoS budget (and
  note as a deployment caveat that the stock 1 ms budget, tuned for classical
  verifiers, is worth revisiting alongside heavier PQ verification). After the
  fix any residual non-200 is a genuine transport failure (`status=0`) or a
  true policy denial, never a wall-clock timeout. The server logs `[403DIAG]`
  (failure class, peer, seq, bearer length) and appends the exact bearer to
  `/tmp/nbsrv_diag.b64`; `reproduce_403.sh` reproduces the defect and
  `verify_fix.sh` confirms its removal under the same high-contention load.
- Report bootstrap 95% CIs for P95/P99; show distributions as boxplots
  (quartiles/median/outliers) for multi-run throughput and as percentile-vs-RTT
  curves for latency.

---

## 8. Output data schemas (written under experiments/data/)

- `net_latency.csv` (E-N1/E-N2/E-N4; column `exp` in {en1,en2,en4}):
  exp,family,profile,root,att,n,mode,rtt_ms,loss_pct,rate,seq,total_ns,
  verify_ns,status. Loss retransmission effects (RQ-N2) are derived from the
  E-N2 tail/amplification analysis joined to E-N5 segment counts; narrowband
  serialization (RQ-N4) is the E-N4 rows joined to token bytes, so no separate
  retrans/bandwidth files are written.
- `net_throughput.csv` (E-N3): profile,family,n,rtt_ms,conc,rep,duration_s,
  completed,failed,rps,p50_ns,p95_ns,p99_ns,verify_mean_ns.
- `net_segments_meas.csv` (E-N5): profile,n,meas_up,meas_dn. Predicted
  N_up=ceil(S_up/MSS), N_dn=1, request byte size and over_cwnd are recomputed
  deterministically in the analysis script from `net_tokens_manifest.csv`
  (profile,family,root,att,n,raw_b,b64_b) and the exact request-header
  template, then compared row-by-row with measurement.
- `net_footprint.csv` (E-N6): backend,binary_b,stripped_b,rss_kb.
- `net_calibrate.csv`: stage,rtt_ms,loss_pct,rate,ping_n,ping_min,ping_avg,
  ping_max,ping_loss_pct.
- `net_meta.txt`: date, kernel, cpu, cores, rustc, cargo profile, mss, cwnd.
Analysis summaries and figures are emitted read-only under
`experiments/netbed/analysis/` and `.../figs/` by `analyze_net.py`.

---

## 9. Pre-registered hypotheses (from existing micro-benchmarks; tested, not assumed)

- **H1.** Verification is hidden by network delay except on near-zero-RTT
  links. For FN-DSA-512 at n=20 the E56 pure-verify time is ≈796 µs (E6
  whole-chain ratio 1.057× over Ed), implying a pure-verify keep-alive
  crossover τ*≈0.8 ms and ρ≈0.14 at τ=5 ms, ρ≈0.04 at τ=20 ms; the network
  t_srv clock (which additionally decodes/parses a multi-KiB token) is a few
  tenths of a ms larger, shifting τ* to roughly 1–1.2 ms — still below a LAN
  RTT. Under either clock the bottleneck on realistic networks is wire size,
  not verification CPU; the exact measured τ* and ρ curves are reported.
- **H2.** newconn latency is dominated by the two round-trips common to every
  scheme; scheme differences at loss 0 come mainly from extra segments /
  slow-start RTTs incurred by oversized uniform SLH/ML-DSA-87 chains.
- **H3.** Tail latency under loss grows with N_up via 1−(1−p)^N: large uniform
  chains (SLH, large-n ML-DSA-87) cross cwnd0 and show marked P99 inflation at
  p=3–5%, while FN-DSA, hybrid and strong-root/light-hop mixed chains stay in
  few segments with flat tails — direct network evidence for the deployment
  recommendations.
- **H4.** At τ=0, single-connection keep-alive throughput is bounded by
  t_srv (pilot: Ed25519 ≈1.1k req/s, FN-DSA-512 ≈0.8k req/s at n=20); the
  pure-verify ratio matches E56/E6 (FN-DSA-512 ≈1.057× Ed per whole-chain
  verification), while the network t_srv ratio is somewhat larger because
  decode/parse grows with token bytes. Concurrency scales with the available
  cores, and at τ≥20 ms the network bounds all schemes to nearly the same
  rate.
- **H5.** On narrow links, t_B dominates and latency tracks S/B linearly;
  mixed/hybrid byte reduction (≥2/3 for the strong-root/light-hop case) yields
  a proportional end-to-end reduction.

Any hypothesis the data contradicts is reported as contradicted, with the
measured value.

---

## 10. Reproduction artefacts

- Rust bins (in `impl/pqbiscuit/src/bin/`): `netbed_gen.rs` (offline token +
  root-key generator), `netbed_server.rs` (HTTP/1.1 verifier),
  `netbed_client.rs` (latency/throughput load generator); shared helpers in
  `src/bin/netbed/common.rs` (included per-bin via `#[path]`).
- Scripts (in `experiments/netbed/`): `netbed_up.sh`, `netbed_set.sh`,
  `netbed_down.sh`, `netbed_run_all.sh` (full matrix, STAGE/QUICK gated,
  idempotent per stage), and `analyze_net.py` (statistics, bootstrap CIs,
  model fits and all network figures read-only from the CSVs).
- Diagnostic harness for the spurious-403 root cause: `reproduce_403.sh`
  (fires 16×1500 new-connection requests at RTT=50 ms, dumps each rejected
  bearer and diffs it byte-for-byte against the on-disk token) and
  `verify_fix.sh` (replays the same high-contention workload in both newconn
  and keep-alive modes and asserts zero non-200 after relaxing the authorizer
  wall-clock limit). `probe_hardening.sh` separately confirms multi-segment
  narrow-band reads and 5%-loss resilience.
- One command brings up the testbed, (re)generates tokens, runs E-N1…E-N6, and
  writes the CSVs; figures are regenerated read-only from the CSVs.

---

## 11. Integration map — network evidence is woven into the narrative, not a plug-in

The network results are the empirical backbone of the Computer Networks frame
("deployability and performance impact of post-quantum signatures on
offline-attenuating capability tokens in network systems"). Each measured
result must appear where it changes an argument, not in a stand-alone
"experiments" island. Pre-registered landing points (numbers filled from the
CSVs; contradicted hypotheses reported as such):

- **Introduction / motivation.** Open with the network question, not the
  cryptography: an offline-attenuating token is verified on the *data path* of
  every authorized request, so what matters operationally is end-to-end
  authorization latency, tail behaviour under loss, server rate and narrow-link
  cost — not isolated verify ns. Cite the measured amortization crossover (H1)
  and the over-cwnd new-connection penalty (H2) as the motivating findings.
- **System/network model (early section).** Carry the §2 transaction
  abstraction (Bearer header, HTTP/1.1 over TCP, newconn vs ka) and the stated
  TLS scope boundary into the paper's model, so the later equations refer to a
  defined deployment rather than appearing with the plots.
- **Design rationale for hybrid / strong-root-light-hop.** These were
  recommended from CPU and token bytes; the network experiments extend the
  justification: staying inside the initial congestion window avoids an extra
  slow-start RTT on cold connections (H2, measured k per profile/n), and fewer
  segments lowers both `P_loss=1−(1−p)^N` and measured P99 inflation at
  p=3–5% (H3). The recommendation is thus shown to hold for *network* reasons,
  not only micro-benchmark reasons — a CN-centred contribution.
- **Deployability / operational guidance.** Give conditional guidance keyed to
  the measured regimes: long-lived service-to-service links (ka) are network-
  bound beyond a ≈1 ms RTT and PQ schemes are indistinguishable in the median;
  cold/short-lived clients with large uniform tokens pay slow-start RTTs;
  narrow IoT links are bound by `t_B=8S/B`, where the ≥2/3 byte reduction of
  mixed chains converts linearly into end-to-end time (H5); server fleets scale
  verification with cores and become network-bound at RTT≥20 ms at c=32 (H4).
- **Footprint / feasibility.** Binary size and peak RSS (E-N6) close the
  deployability question for constrained verifiers.
- **Discussion/limitations.** Keep the HTTP-vs-TLS boundary, single-host netns
  fidelity (controlled, not a planet-scale trace), and the offline-signing
  exclusion explicit; report any hypothesis the data contradict.
- **Conclusion/abstract.** Replace generic "we migrated to PQ" claims with the
  quantitative network statements (crossover RTT, over-cwnd penalty, tail
  amplification, narrow-link savings, throughput regime) produced here.

Every numeric statement in these passages must trace to a CSV/summary emitted by
`analyze_net.py` and agree with the existing micro-benchmark numbers already in
the manuscript; the three verification clocks (t_srv / E6 whole-chain / E56
pure-verify) are kept distinct wherever a ratio is quoted.
