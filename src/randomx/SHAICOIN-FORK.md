# Shaicoin RandomX (vendored fork)

This directory is a **vendored fork** of upstream RandomX, committed directly into the
Shaicoin source tree (it is intentionally **not** a git submodule) so that the
Shaicoin-specific parameters are always present in any clone/checkout. A submodule
would point at upstream and a fresh clone would build a *different* (incompatible)
RandomX — see the audit note below.

## Upstream base

- Repository: https://github.com/tevador/RandomX
- Version: **v2.0.1** (tag `v2.0.1`, commit `aaafe71322df6602c21a5c72937ac284724ae561`)
- This is the latest v2 **release** as of vendoring (2026-07). Upstream `master` has
  only unreleased post-2.0.1 commits, which are deliberately not used on mainnet.
- License: BSD-3-Clause (see `LICENSE`, retained unchanged).

The engine (VM, dataset/cache generation, JIT compilers, hashing) is **unmodified**
from upstream v2.0.1. Only the two configuration files below are changed.

## Shaicoin modifications

Both files carry identical values (the `.asm` copy feeds the x86 static JIT; the `.h`
copy feeds the interpreter and the ARM64/RISC-V JITs — they MUST match or JIT and
interpreter produce different hashes → chain split).

### `src/configuration.h` and `src/asm/configuration.asm`

1. **Argon2 salt** (domain separation from Monero, so Monero hashpower/ASICs/pools
   cannot be repointed at Shaicoin):
   - upstream: `"RandomX\x03"`
   - Shaicoin: `"ShaicoinRandomX-v2\x01"`  (19 bytes; `static_assert(ArgonSaltSize >= 8)` holds)

2. **Instruction frequency rebalance** (further domain separation; sum stays 256,
   enforced by `static_assert(wtSum == 256)` in `src/common.hpp`):
   | constant            | upstream | Shaicoin |
   |---------------------|----------|----------|
   | `RANDOMX_FREQ_IROR_R` | 8      | 5        |
   | `RANDOMX_FREQ_IROL_R` | 2      | 5        |
   | `RANDOMX_FREQ_FADD_R` | 16     | 17       |
   | `RANDOMX_FREQ_FADD_M` | 5      | 4        |
   | `RANDOMX_FREQ_FSUB_R` | 16     | 15       |
   | `RANDOMX_FREQ_FSUB_M` | 5      | 6        |

   Other RandomX parameters (scratchpad sizes, `CACHE_ACCESSES`, `SUPERSCALAR_LATENCY`,
   dataset/program/argon sizes, and the remaining instruction frequencies) are unchanged.
   See `doc/randomx-fork-audit.md` for the integration reference and review scope.

## Updating from upstream

RandomX is customized, so you cannot blindly pull upstream. To take an upstream fix:

1. Diff the target upstream tag against v2.0.1 for `src/configuration.h`,
   `src/asm/configuration.asm`, and anything that changes the hash.
2. Re-apply the two Shaicoin edits above (keep `.h` and `.asm` in sync).
3. Re-verify determinism (JIT vs interpreter, and across x86/ARM64/RISC-V).
4. Regenerate the Shaicoin known-answer test vectors and update the Shaicoin unit test.
5. Only then bump the vendored copy.

## Known-answer test vector (pin this in CI)

Upstream's self-tests in `src/tests/tests.cpp` are guarded by
`stringsEqual(RANDOMX_ARGON_SALT, "RandomX\x03")` and therefore **self-disable** with
the Shaicoin salt. Pin the following Shaicoin-specific known-answer vector in a unit
test so a wrong/rolled-back config fails CI instead of silently splitting the chain.

Computed against this vendored tree (light mode, `randomx_get_flags() | RANDOMX_FLAG_V2`;
RandomX guarantees the hash is identical across light/fast, JIT/interpreter, and all
architectures):

```
key   = "shaicoin-randomx-kat-key-v1"   (27 bytes, no NUL)
input = "shaicoin-randomx-kat-input-v1" (29 bytes, no NUL)
hash  = 1e3ede7f49c31a77fe72bc54441f490da2a158a1d8ea7920c2bd46c80ea6bad2
```

For reference, **stock** RandomX v2 (salt `"RandomX\x03"`, upstream frequencies)
produces `d6f97cc88f167c7917c6982b7e8ca5f0d82b8cefbf0242d18b34a5edfe92f265` for the
same key/input — confirming the Shaicoin parameters are active and domain-separated.
If your build ever reproduces the stock hash, the custom config was lost (e.g. a
submodule reset) — treat it as a release blocker.
