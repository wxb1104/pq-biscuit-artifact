#!/usr/bin/env python3
"""
PQ-Biscuit token-size model (E2/E3/E4 size part).

Reads REAL per-algorithm measurements from data/algostats.csv (produced by the
Rust PQClean benchmark) and applies the EXACT Biscuit block-chain byte structure
from SPECIFICATIONS.md:

  Biscuit { authority: SignedBlock; blocks[]: SignedBlock; proof: Proof }
  SignedBlock { block:data; nextKey:PublicKey{alg,pk}; signature:sig ; externalSignature? }
  Proof = nextSecret(sk of last key)   [attenuable]
        | finalSignature(sig by last key over last block+prev sig) [sealed]

Per-block bytes = data || (algid||pk) || sig, each a length-delimited protobuf field.
The root public key is held by the verifier (rootKeyId) and is NOT in the token.

protobuf tag/length overhead is modelled explicitly and reported; it is tiny
relative to KB-scale PQ signatures, and will be calibrated against the real
biscuit-rust integration (E5). Latency is measured, not modelled (see figures).
"""
import csv, os, argparse, json

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
os.makedirs(DATA, exist_ok=True)

# ---- structural constants (bytes) ----
ALGID = 1          # PublicKey.Algorithm enum (varint; <128 -> 1 byte)
BLOCK_WRAP = 2     # nested SignedBlock tag/len slack per block
TOKEN_WRAP = 8     # Biscuit top-level field tags/lengths + rootKeyId slack
HYB_LABEL = 8      # labelled hybrid combiner: domain-separation label + 2 length prefixes
DATA_AUTHORITY = 120   # typical authority Datalog block payload (sensitivity-tested)
DATA_ATTEN = 90        # typical attenuation block payload

PQ_ORDER = ["ed25519", "mldsa44", "mldsa65", "mldsa87",
            "fndsa512", "fndsa1024",
            "slhdsa128s", "slhdsa128f", "slhdsa256s", "slhdsa256f"]
MIXED_PAIRS = [("slhdsa128s", "fndsa512"), ("slhdsa128s", "mldsa44"),
               ("mldsa87", "fndsa512"), ("mldsa87", "mldsa44"),
               ("slhdsa256s", "fndsa512")]
BUDGETS = [4096, 8192, 16384]


def load_stats(path=os.path.join(DATA, "algostats.csv")):
    s = {}
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            for k in ("pk", "sk", "sig"):
                r[k] = int(r[k])
            s[r["variant"]] = r
    # FN-DSA (Falcon) detached signatures are variable-length in PQClean; a token
    # must be sized for the FIPS 206 fixed (padded) maximum. Keep the measured
    # typical length aside for the paper table.
    fips_sig_cap = {"fndsa512": 666, "fndsa1024": 1280}
    for v, cap in fips_sig_cap.items():
        if v in s:
            s[v]["sig_measured"] = s[v]["sig"]
            s[v]["sig"] = cap
    return s


def field_len(b: int) -> int:
    """protobuf field = tag(1) + varint length + payload; varint len by size."""
    if b < 128:
        return 1 + 1 + b
    if b < 16384:
        return 1 + 2 + b
    return 1 + 3 + b


def block_bytes(data: int, pk: int, sig: int) -> int:
    return field_len(data) + field_len(ALGID + pk) + field_len(sig) + BLOCK_WRAP


def hybrid_mats(base, ed):
    pk = ed["pk"] + base["pk"] + 2
    sig = ed["sig"] + base["sig"] + HYB_LABEL
    sk = ed["sk"] + base["sk"] + 2
    return pk, sig, sk


def uniform_size(st, variant, n, mode, hybrid=False, thirdparty=0,
                 da=DATA_AUTHORITY, dt=DATA_ATTEN):
    s = st[variant]
    if hybrid:
        pk, sig, sk = hybrid_mats(s, st["ed25519"])
    else:
        pk, sig, sk = s["pk"], s["sig"], s["sk"]
    total = block_bytes(da, pk, sig)
    total += n * block_bytes(dt, pk, sig)
    total += field_len(sk) if mode == "attenuable" else field_len(sig)
    total += thirdparty * (field_len(ALGID + pk) + field_len(sig))
    return total + TOKEN_WRAP


def mixed_size(st, rootv, ephev, n, mode, da=DATA_AUTHORITY, dt=DATA_ATTEN):
    r, e = st[rootv], st[ephev]
    # authority block: signed by root key r, carries next ephemeral key e
    total = block_bytes(da, e["pk"], r["sig"])
    total += n * block_bytes(dt, e["pk"], e["sig"])
    total += field_len(e["sk"]) if mode == "attenuable" else field_len(e["sig"])
    return total + TOKEN_WRAP


def max_blocks(size_fn, budget, cap=512):
    lo = 0
    for n in range(0, cap + 1):
        if size_fn(n) <= budget:
            lo = n
        else:
            break
    return lo


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nmax", type=int, default=20)
    args = ap.parse_args()
    st = load_stats()
    have = set(st)
    rows, cap_rows = [], []

    def add(scenario, variant, mode, n, size, thirdparty=0):
        rows.append(dict(scenario=scenario, variant=variant, mode=mode,
                         n=n, thirdparty=thirdparty, size_bytes=size))

    ns = range(0, args.nmax + 1)
    # (a) pure uniform chains, incl. Ed25519 baseline
    for v in PQ_ORDER:
        if v not in have:
            continue
        for mode in ("sealed", "attenuable"):
            for n in ns:
                add("pure", v, mode, n, uniform_size(st, v, n, mode))
            for t in (1, 2, 3):
                add("pure-tp", v, mode, 2,
                    uniform_size(st, v, 2, mode, thirdparty=t), thirdparty=t)
    # (b) hybrid Ed25519 + PQ uniform chains
    for v in PQ_ORDER:
        if v == "ed25519" or v not in have:
            continue
        for mode in ("sealed", "attenuable"):
            for n in ns:
                add("hybrid", "ed25519+" + v, mode, n,
                    uniform_size(st, v, n, mode, hybrid=True))
    # (c) mixed chains: conservative root, small ephemeral attenuation keys
    for rootv, ephev in MIXED_PAIRS:
        if rootv not in have or ephev not in have:
            continue
        name = rootv + ">" + ephev
        for mode in ("sealed", "attenuable"):
            for n in ns:
                add("mixed", name, mode, n, mixed_size(st, rootv, ephev, n, mode))

    with open(os.path.join(DATA, "token_size.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["scenario", "variant", "mode",
                                          "n", "thirdparty", "size_bytes"])
        w.writeheader(); w.writerows(rows)

    # capacity thresholds
    scenarios = []
    for v in PQ_ORDER:
        if v in have:
            scenarios.append(("pure", v, lambda n, v=v, m=None: uniform_size(st, v, n, "sealed")))
            if v != "ed25519":
                scenarios.append(("hybrid", "ed25519+" + v,
                                  lambda n, v=v: uniform_size(st, v, n, "sealed", hybrid=True)))
    for rootv, ephev in MIXED_PAIRS:
        if rootv in have and ephev in have:
            scenarios.append(("mixed", rootv + ">" + ephev,
                              lambda n, a=rootv, b=ephev: mixed_size(st, a, b, n, "sealed")))
    for scenario, variant, fn in scenarios:
        for budget in BUDGETS:
            cap_rows.append(dict(scenario=scenario, variant=variant,
                                 mode="sealed", budget=budget,
                                 max_n=max_blocks(fn, budget)))
    with open(os.path.join(DATA, "capacity.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["scenario", "variant", "mode",
                                          "budget", "max_n"])
        w.writeheader(); w.writerows(cap_rows)

    meta = dict(DATA_AUTHORITY=DATA_AUTHORITY, DATA_ATTEN=DATA_ATTEN,
                ALGID=ALGID, BLOCK_WRAP=BLOCK_WRAP, TOKEN_WRAP=TOKEN_WRAP,
                HYB_LABEL=HYB_LABEL, budgets=BUDGETS, nmax=args.nmax)
    with open(os.path.join(DATA, "model_meta.json"), "w") as f:
        json.dump(meta, f, indent=2)
    print("wrote data/token_size.csv (%d rows), data/capacity.csv (%d rows)"
          % (len(rows), len(cap_rows)))


if __name__ == "__main__":
    main()
