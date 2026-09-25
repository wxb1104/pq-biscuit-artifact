# PQ-Biscuit — Artifact / Reproducibility Package

Companion code and data for:

> **Post-Quantum Biscuit: Network Deployability and Performance of Post-Quantum Signatures for Offline-Attenuating Capability Tokens**

This package reproduces every measurement and functional test reported in the
paper. It contains the post-quantum (PQ) migration of the Biscuit capability
token, the measurement harnesses, the raw measurement data, and the analysis
and plotting scripts that fit the analytic models and render the paper's
experimental figures. No result is hard-coded: the Rust harnesses emit raw CSV,
the analysis scripts derive fitted tables from that CSV, and the redraw scripts
render every figure from those outputs.

## 1. What is reproduced

1. **Functional fidelity / security bindings** — for every signature
   algorithm, the migrated token preserves Biscuit's seal/attenuate/verify
   semantics, Datalog allow/deny behaviour, root-key binding, tamper
   rejection, third-party block rules and hybrid cross-combination rejection,
   extended by structural checks (f10–f11), an algorithm-policy downgrade
   test (f12) and a 6000-mutation property-based fuzzing campaign that records
   zero parser or authorization escapes.
2. **End-to-end cost** — authority build, per-hop append, seal, full-chain
   verification and Datalog authorisation latency versus attenuation depth,
   for pure-PQ, hybrid classical/PQ and mixed chains.
3. **Two build targets** — the default **AVX2** PQClean kernels and a
   SIMD-less **portable** `clean`-C build.
4. **Serialized token size, transport capacity and wire budget** —
   unsealed/sealed size vs depth, fit of the per-hop linear size model, the
   maximum hops that fit a cookie/header budget, and the raw/base64url/
   Authorization-field byte budget compared with the default single-header
   limits of nginx, AWS ALB and Cloudflare.
5. **Offline key pre-generation** — the fraction of per-hop online cost
   removed when attenuation key pairs are pre-minted offline.
6. **FN-DSA signature-length spread** — measured variable-length signatures
   against the FIPS 206 cap.
7. **Standalone primitive baseline** — key/signature sizes and
   keygen/sign/verify timings of the underlying NIST primitives (PQClean).
8. **Network data-path deployability** — end-to-end authorization latency and
   its tail over emulated round-trip time and packet loss, sustained verifier
   throughput versus concurrency, completion time over rate-limited links, wire
   segmentation, and verifier memory/binary footprint, measured behind a
   dependency-free HTTP/1.1 authorization service in a two-namespace testbed.
9. **Statistical confidence** — non-parametric bootstrap 95% intervals
   (10,000 resamples, fixed seeds) for every reported latency, chain-verify
   cost, pre-generation saving, hybrid overhead, loss tail, throughput and
   constrained-link completion.

## 2. Repository layout

```
pq-biscuit-artifact/
├── README.md
├── impl/
│   └── pqbiscuit/                     # migrated Biscuit crate + measurement binaries
│       ├── Cargo.toml  Cargo.lock
│       ├── src/
│       │   ├── main.rs                # end-to-end demonstration binary (not timed)
│       │   └── bin/                   # measurement harnesses
│       └── vendor/
│           ├── biscuit-auth/          # vendored, PQ-extended Eclipse biscuit-auth
│           └── biscuit-parser/        # vendored, PQ-extended Eclipse biscuit-parser
└── experiments/
    ├── netbed/                        # network data-path testbed
    │   ├── netbed_up.sh / netbed_set.sh / netbed_down.sh  # namespaces + qdisc
    │   ├── netbed_run_all.sh          # E-N1..E-N6 matrix (per-stage resume)
    │   ├── analyze_net.py             # network analysis -> derived CSV
    │   ├── redraw_net.py              # network figures netfig1-5
    │   ├── NETBED_PROTOCOL.md         # frozen protocol, formulas, statistics
    │   ├── figs/netfig1-5.png         # network figures
    │   └── analysis/                  # derived per-stage summary CSV
    ├── pqbench/                       # standalone primitive benchmark -> algostats.csv
    ├── scripts/                       # one-command measurement reproduction
    │   ├── common.sh
    │   ├── 01_primitives.sh
    │   ├── 02_measure_avx2.sh
    │   ├── 03_measure_portable.sh
    │   ├── 04_analyze.sh
    │   ├── run_all.sh
    │   ├── ci_bootstrap.py            # bootstrap CIs for micro timings
    │   ├── ci2_pregen_hybrid.py       # CIs for pregen saving & hybrid overhead
    │   ├── ci3_network.py             # CIs for network latency/loss/throughput
    │   ├── ci_n20_verify_rtt0.py      # zero-RTT chain-verify baseline CIs
    │   └── budget_size.py             # raw/base64/header wire budget
    ├── analysis/                      # bootstrap CI and wire-budget result CSV
    ├── data/                          # raw CSV (harness output) + derived CSV/JSON
    ├── figures/                       # paper figures (content-named; see table below)
    ├── figstyle.py                    # shared Okabe-Ito style, semantic colours, labels
    ├── redraw_micro.py               # token-layer figures (11) -> figures/
    ├── redraw_profiles.py            # deployment-profile figure -> figures/
    ├── model_tokens.py                # shared token-size model & budget constants
    ├── calibrate_e55.py               # size/latency calibration & capacity
    ├── analyze_mixed_e55.py           # mixed-chain fits
    ├── analyze_hybrid_e55.py          # hybrid size/latency fits
    ├── analyze_formal_e56.py          # AVX2/portable, phases, fits, FN length
    └── analyze_e6.py                  # fidelity/pregen/profiles fits
```

The harness binaries write to the relative path `../../experiments/data`, so
the `impl/pqbiscuit` ↔ `experiments` directory relationship must be preserved
(it is, in this layout).

## 3. Requirements

* **Rust toolchain** that supports Cargo `edition = "2024"` (Rust ≥ 1.85). The
  first build downloads the `pqcrypto-*`, `ed25519-dalek` and supporting
  crates from crates.io; `biscuit-auth`/`biscuit-parser` are vendored locally
  and are **not** downloaded.
* A **C compiler** (the PQClean implementations are C). AVX2 support is used
  by the default build; the portable build needs no SIMD.
* **Python 3** with `pandas`, `numpy`, `matplotlib`:
  ```bash
  python3 -m pip install pandas numpy matplotlib
  ```
* **Linux**: optional `taskset` (util-linux) to pin measurements to one core;
  `coreutils`/`bash`. On **macOS** `taskset` is absent and pinning is skipped
  automatically. On **Windows**, run the scripts under **WSL** (the timings in
  the paper were collected under Linux/WSL2).

## 4. Quick start

Measurement and analysis:

```bash
cd pq-biscuit-artifact/experiments/scripts
bash run_all.sh
```

This runs, in order: primitive benchmark → AVX2 token measurements → portable
token measurements (the vendor manifest is patched and automatically
restored) → analysis. Raw CSV lands in `experiments/data`, fitted tables in
`experiments/data` and the analysis outputs.

Figures are then rendered in a separate step through the shared style:

```bash
cd pq-biscuit-artifact/experiments
python3 redraw_micro.py        # 11 token-layer figures -> figures/
python3 redraw_profiles.py     # deployment-profile figure -> figures/
```

The full Rust sweep compiles PQClean once and performs thousands of token
operations (the four stateless-hash SLH-DSA sets dominate the run time); the
Python analysis and plotting take only seconds. To reproduce only the analysis
and figures from the committed raw data:

```bash
cd pq-biscuit-artifact/experiments
bash scripts/04_analyze.sh     # all five analysis scripts
python3 redraw_micro.py && python3 redraw_profiles.py
```

### Network data-path experiments

The network matrix needs root (network namespaces and `tc`); on Windows run it
under WSL2. From the repository root:

```bash
(cd impl/pqbiscuit && cargo build --release)              # one-time build
sudo bash experiments/netbed/netbed_run_all.sh           # STAGE=all
#   one stage:   sudo STAGE=en1 bash experiments/netbed/netbed_run_all.sh
python3 experiments/netbed/analyze_net.py                # derived CSV
python3 experiments/netbed/redraw_net.py                 # netfig1-5
```

The six stages are E-N1 latency vs round-trip time, E-N2 latency vs loss, E-N3
throughput vs concurrency, E-N4 completion time over shaped links, E-N5 wire
segmentation, and E-N6 footprint; each is independently resumable. Offline
tokens and root keys are generated by `netbed_gen` on the first run into
git-ignored `experiments/netbed/{tokens,rootkeys}`. To regenerate only the
network figures from the committed raw CSV, `analyze_net.py` then
`redraw_net.py` take a few seconds.

## 5. Step-by-step

| Step | Script | Rust binaries run | Primary outputs |
|------|--------|-------------------|-----------------|
| 1 | `01_primitives.sh` | `pqbench` | `data/algostats.csv` |
| 2 | `02_measure_avx2.sh` | `e55_bench`, `e55_hybrid_bench`, `e55_mixed`, `e6_fidelity`, `e6_pregen`, `e6_profiles`, `e56_formal avx2` | `data/e55_*`, `data/e56_*_avx2`, `data/e6_*` |
| 3 | `03_measure_portable.sh` | `e56_formal portable` (separate target, manifest patched then restored) | `data/e56_*_portable` |
| 4 | `04_analyze.sh` | — (Python) | fitted `formal_*`/`capacity_*`/`*_summary.*` |
| 5 | `redraw_micro.py`, `redraw_profiles.py` | — (Python) | `figures/` (content-named) |

Build artifacts are kept out of the tree under `.target/` (override with the
`CARGO_TARGET_DIR` environment variable). On Linux, set `PIN_CORE` to pin to a
different core (default `2`). `e6_fidelity` exits non-zero if any functional
check fails.

## 6. Experimental design

**Algorithms (12 evaluated at the token layer).** The classical Ed25519
baseline; NIST-standardized **ML-DSA**-44/65/87 and **SLH-DSA**-128s/128f/
256s/256f; draft **FN-DSA**-512/1024; and two hybrid combos
Ed25519+ML-DSA-44 and Ed25519+FN-DSA-512. (The wire format defines one more
algorithm code point than the twelve evaluated here.) The standalone
`pqbench` additionally reports the nine NIST parameter sets without the token
layer.

**Attenuation depths.** Size sweeps cover `n = 0..20`; latency is sampled on
the grid `n ∈ {0,1,2,5,10,20}`.

**Repetitions (exact constants live at the top of each binary).** Fast
schemes (Ed25519/ML-DSA/FN-DSA/hybrids) use 101 timing repetitions after
warm-up; the deliberately slow stateless SLH-DSA sets use a reduced grid
(`n ∈ {0,1,2}`) and 5 repetitions for the token sweeps (21/3 for the
pre-generation harness). The deployment-profile harness uses 51 verification
repetitions (10 warm-up); the FN-DSA length spread uses 51 sealed tokens.
`pqbench` uses 20–1000 primitive iterations depending on scheme cost.

**Statistics.** Timing harnesses record either medians or **raw per-repetition
nanosecond samples**; the analysis reports median, Q1/Q3 (IQR) and extrema.
Measurements are single-threaded and, on Linux, pinned to one physical core to
reduce scheduler jitter.

**Deployment profiles (`e6_profiles`).** `all-ed`, `all-mldsa44`,
`all-fndsa512`, `hybrid-ed-mldsa44`, `hybrid-ed-fndsa512`, and the two mixed
strategies `mixed-mldsa87-root-fn` and `mixed-slh128s-root-fn` (a strong root
signed once offline, compact FN-DSA-512 on every ephemeral hop).

**Fidelity matrix (`e6_fidelity`).** Nine checks per algorithm: f1 mints,
attenuates two hops, seals and repasses; f2 Datalog write-denied; f3 unsealed
round-trip with continued attenuation; f4 key byte round-trip; f5 wrong-root
rejection; f6 tamper rejection (byte flips at five positions 0.05/0.25/0.50/
0.75/0.99); f7 third-party PQ block accepted with the matching external key;
f8 third-party mismatched key rejected; f9 hybrid cross-combination rejected
(hybrid combos only). This yields 98 applicable checks (the hybrid-only checks
are N/A for the other ten algorithms) — all PASS.

**Pre-generation (`e6_pregen`).** On a fixed `n = 2` token it times three
black boxes — `keygen`, `append_realtime` (fresh keygen + append) and
`append_sign` (append with a pre-minted key) — so the analysis can check
additivity (`append_realtime ≈ keygen + append_sign`) and the amortised
saving.

**AVX2 vs portable.** `e56_formal` takes the build tag as its first argument
(`avx2`/`portable`). The portable build compiles the three `pqcrypto` crates
with `default-features = false, features = ["std"]`, linking only PQClean's
SIMD-less `clean` C kernels in a separate target directory.

**Network testbed.** Two network namespaces (`nbS` server, `nbC` client) are
joined by a veth pair (MTU 1500, MSS $M=1460$); `netem` emulates round-trip
time $\tau$ and independent Bernoulli loss on the client egress, while a
token-bucket `tbf` shaper constrains narrow links. A dependency-free HTTP/1.1
server verifies the token and evaluates the Datalog policy for every request,
with the token in `Authorization: Bearer <base64url>`. End-to-end latency is
modelled as $L_{\mathrm{new}}(\tau)\approx\tau+t_{\mathrm{off}}+t_{\mathrm{srv}}$
on a fresh connection and $L_{\mathrm{ka}}(\tau)\approx\tau/2+t_{\mathrm{srv}}$
over a kept connection: the server cost $t_{\mathrm{srv}}$ is paid once per
transaction and is therefore amortized as $\tau$ grows. The matrix sweeps
$\tau\in\{1,5,20,50,100,200\}$ ms, loss $\in\{0,1,3,5\}\%$, rates down to
46 kbps, and concurrency to 32, reporting medians and high percentiles. veth
segmentation offloads are disabled so a wire capture shows real MSS-sized
segments, counted against $N_{\uparrow}=\lceil S_{\uparrow}/M\rceil$.

## 7. Mapping to paper figures, tables and headline results

The paper keeps five data figures for trends that need a curve, together with
the mechanism figure, and reports point values in three compact summary tables
produced by `experiments/scripts/build_tables.py` from the fitted analysis CSVs.
The full per-scheme line plots remain reproducible from the raw data with the
redraw scripts, which is why they are not all carried as separate figures.

| Paper figure / table / claim | Raw data | Analysis → output |
|---|---|---|
| Mechanism figure (design section) | — | token/block flow schematic |
| Fig: size vs depth (affine model, Eq. 15) | `e55_token_size.csv`, `e56_size_*.csv` | `analyze_formal_e56.py` → `formal_size_fit.csv`; `redraw_micro.py` → `size_vs_n.png` |
| Table: cryptographic microbenchmark (per-hop $b$, verify AVX2/portable, pregen $\eta$) | `e56_latency_*.csv`, `e6_pregen.csv`, `e56_fnlen_*.csv`, `e55_hybrid_*.csv` | fitted slopes/speedups; **`scripts/build_tables.py` → `table_fragments/table_micro.tex`** |
| Fig: end-to-end latency vs RTT (cost amortized) | `net_latency.csv` | `analyze_net.py` → `en1_summary/fits`; `redraw_net.py` → `netfig1_latency_rtt.png` |
| Fig: loss inflates the tail, 0% failures | `net_latency.csv` | `analyze_net.py` → `en2_loss`; `redraw_net.py` → `netfig3_loss.png` |
| Fig: throughput, verification-bound → network-bound | `net_throughput.csv` | `analyze_net.py` → `en3_throughput`; `redraw_net.py` → `netfig4_throughput.png` |
| Table: network effects ($t_{\rm srv}$, $\rho$, loss p99, 46 kbps, RSS) | `net_latency.csv`, `net_footprint.csv` | `analyze_net.py` → en1/en2/en4/en6; **`build_tables.py` → `table_net.tex`** |
| Fig: deployment profiles | `e6_profiles_size.csv`, `e6_profiles_verify.csv` | `analyze_e6.py`; `redraw_profiles.py` → `profiles.png` |
| Table: deployment profiles ($S_{10}/S_{20}/V_{20}$, 4/8/16 KiB fit) | `e6_profiles_*.csv` | **`build_tables.py` → `table_prof.tex`** |
| Mixed strong-root/FN chains (>=2/3 size saving at depth 10) | `e55_mixed.csv` | `analyze_mixed_e55.py` → `e55_mixed_summary.json` (values in profile table/text) |
| Fidelity: 98 applicable checks PASS, 6000 fuzz, 0 escape | `e6_fidelity.csv`, `e6_fuzz.csv` | `analyze_e6.py` → `e6_summary.json` (reported in text) |
| Wire segmentation matches $\lceil S/M\rceil$ | `net_segments_meas.csv` | `analyze_net.py` → `en5_segments.csv` |
| Hybrid size/latency point values | `e55_hybrid_size.csv`, `e55_hybrid_latency.csv` | `analyze_hybrid_e55.py` (values in micro table) |
| Cookie/header capacity | size models | `calibrate_e55.py` → `capacity_e55.csv` (values in profile table) |
| Primitive sizes/timings (FIPS cross-check) | `algostats.csv` | reported directly |

The three `table_fragments/*.tex` files are the exact table environments used in
the manuscript; regenerate them after any re-run with
`python3 experiments/scripts/build_tables.py`.

The committed `data/` and `figures/` are the reference run used for the paper.
Serialized sizes and pass/fail outcomes are deterministic and reproduce
exactly; wall-clock medians are hardware dependent and vary, while the fitted
slopes and ratios are stable across machines.

## 8. Data reference

Raw harness output:

| File | Columns |
|---|---|
| `algostats.csv` | family, variant, level, pk, sk, sig, keygen/sign/verify median & p95 (µs), samples |
| `e55_token_size.csv`, `e55_hybrid_size.csv` | alg, n, unsealed_bytes, sealed_bytes |
| `e55_latency.csv`, `e55_hybrid_latency.csv` | alg, n, phase, median_ns, reps (phases: authority_build, append_hop, seal, verify_chain, authorize) |
| `e55_mixed.csv` | root, atten, n, sealed_bytes, verify_median_us, reps |
| `e56_latency_<tag>.csv` | alg, op, n, ns (one raw sample per row) |
| `e56_size_<tag>.csv` | alg, n, unsealed_bytes, sealed_bytes |
| `e56_fnlen_<tag>.csv` | alg, iter, sealed_n0 |
| `e6_fidelity.csv` | alg, check, result (PASS/FAIL), detail |
| `e6_pregen.csv` | alg, phase (keygen/append_realtime/append_sign), rep, ns |
| `e6_profiles_size.csv` | profile, n, size_bytes |
| `e6_profiles_verify.csv` | profile, n, rep, ns |
| `net_latency.csv` | exp,family,profile,root,att,n,mode,rtt_ms,loss_pct,rate,seq,total_ns,verify_ns,status |
| `net_throughput.csv` | profile,family,n,rtt_ms,conc,rep,duration_s,completed,failed,rps,p50/p95/p99_ns,verify_mean_ns |
| `net_segments_meas.csv` | profile,n,meas_up,meas_dn |
| `net_footprint.csv` | backend,binary_b,stripped_b,rss_kb |
| `net_calibrate.csv` | stage,rtt_ms,loss_pct,rate,ping_min/avg/max,ping_loss_pct |

Fitted analysis output: `formal_verify_slopes.csv` (per-signature slope,
intercept, R²), `formal_phases_n2.csv`, `formal_speedup.csv` (portable/AVX2
ratio), `formal_size_fit.csv`, `formal_fnlen.csv`, `capacity_e55.csv`, and the
`*_summary.json` files. `<tag>` is `avx2` or `portable`. Network fitted output
lives in `experiments/netbed/analysis/` (`en1_summary.csv`, `en1_fits.csv`,
`en2_loss.csv`, `en3_throughput.csv`, `en4_bandwidth.csv`, `en5_segments.csv`,
`en6_footprint.csv`), with the five network figures under
`experiments/netbed/figs/`.

## 9. Figure style

All figures use a single shared specification, `figstyle.py`: a colour-blind
safe Okabe-Ito palette assigned by cryptographic family (classical baseline,
ML-DSA, FN-DSA, SLH-DSA, hybrid, mixed), no background grid, direct end-of-line
labels (with automatic collision avoidance for the profile figure), and small
multiples for the depth sweeps so that curves never overlap. Colour is never
the sole cue: families also differ by marker and line style.

## 10. Determinism and troubleshooting

* **Sizes are deterministic**; they depend only on the algorithm, depth and
  profile. The FN-DSA length spread is the one intentional exception.
* **Timings vary** with CPU, clock, load and core pinning; report medians/IQR
  and prefer a quiet, single-core run.
* The portable step edits `vendor/biscuit-auth/Cargo.toml` temporarily and
  restores it via a trap even on failure; the AVX2 and portable builds use
  separate target directories and never overwrite each other.
* If a build cannot find a C compiler or SIMD headers, build the portable
  target (clean C) instead; it has no SIMD requirement.

## 11. Code provenance

`impl/pqbiscuit/vendor/biscuit-auth` and `.../biscuit-parser` are vendored from
the Eclipse Biscuit project and retain their upstream licenses; the
post-quantum migration lives in these crates (new `Algorithm` variants for
ML-DSA/SLH-DSA/FN-DSA and the hybrid combos, per-block algorithm identifiers
and next-key/signature bindings, third-party and sealed-token handling, and the
PQClean-backed signature integration). The network data-path harnesses
`netbed_gen`, `netbed_server`, and `netbed_client` (with shared
`netbed/common.rs`), the `experiments/netbed` scripts, and `analyze_net.py` /
`redraw_net.py` are the network measurement code; `impl/pqbiscuit/src/bin` and
`experiments/pqbench` are the token-layer and standalone measurement code.
