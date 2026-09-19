#!/usr/bin/env bash
# Step 3 - portable (SIMD-less PQClean "clean" C kernels) measurement.
# Temporarily sets default-features=false / features=["std"] on the three
# pqcrypto crates in the vendored biscuit-auth manifest, builds e56_formal in a
# SEPARATE target dir, runs it with tag "portable", and ALWAYS restores the
# manifest (trap), leaving the AVX2 build untouched.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$HERE/common.sh"
export CARGO_TARGET_DIR="$PORTABLE_TARGET"

MAN="$IMPL/vendor/biscuit-auth/Cargo.toml"
BAK="$(mktemp)"
cp "$MAN" "$BAK"
restore() { cp "$BAK" "$MAN"; rm -f "$BAK"; echo "[03] restored vendor Cargo.toml"; }
trap restore EXIT

python3 - "$MAN" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
for crate in ("pqcrypto-dilithium", "pqcrypto-falcon", "pqcrypto-sphincsplus"):
    pat = re.compile(
        r"(\[dependencies\." + re.escape(crate) + r"\]\s*\nversion\s*=\s*\"[^\"]+\"\s*\n)",
        re.M)
    def add(m):
        block = m.group(1)
        if "default-features" in block:
            return block
        return block.rstrip("\n") + '\ndefault-features = false\nfeatures = ["std"]\n'
    s, n = pat.subn(add, s, count=1)
    assert n == 1, f"section not found for {crate} ({n})"
open(p, "w", encoding="utf-8").write(s)
print("[03] patched 3 pqcrypto deps -> default-features=false, features=[std]")
PY

cd "$IMPL"
cargo build --release --bin e56_formal
runbin e56_formal portable
echo "[03] portable measurements complete"
