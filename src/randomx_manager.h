// Copyright (c) 2024 The Shaicoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SHAICOIN_RANDOMX_MANAGER_H
#define SHAICOIN_RANDOMX_MANAGER_H

#include <uint256.h>
#include <hash.h>
#include <consensus/params.h>
#include <sync.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdocumentation"
#include <randomx.h>
#pragma clang diagnostic pop
#include <array>
#include <list>
#include <memory>
#include <mutex>
#include <vector>

class CBlockIndex;

struct RandomXKeyContext {
    int key_block_height{0};
    uint256 key_block_hash;
    bool key_block_found{false};
    std::array<uint8_t, Consensus::RANDOMX_KEY_MAX_BYTES> key{};
};

int GetRandomXKeyBlockHeight(int height);

RandomXKeyContext LookupRandomXKeyContext(int height, const CBlockIndex* pindexPrev);

std::array<uint8_t, Consensus::RANDOMX_KEY_MAX_BYTES> DeriveRandomXKey(const uint256& keyBlockHash);

uint256 ComputeRandomXHash(const std::array<uint8_t, Consensus::RANDOMX_KEY_MAX_BYTES>& key,
                           const void* input, size_t inputSize);

/**
 * A per-thread RandomX virtual machine for the *mining* hot path.
 *
 * It owns its own randomx_vm and holds shared_ptr references to the cache and
 * dataset it was built from, so those buffers stay alive for as long as this VM
 * exists even if the manager rotates to a different key concurrently. Hashing
 * through a MiningVM takes NO lock — each mining thread owns one and hammers it
 * independently, giving near-linear multi-core scaling. Move-only.
 */
class MiningVM {
public:
    MiningVM() = default;
    ~MiningVM() { reset(); }
    MiningVM(const MiningVM&) = delete;
    MiningVM& operator=(const MiningVM&) = delete;
    MiningVM(MiningVM&& o) noexcept { move_from(o); }
    MiningVM& operator=(MiningVM&& o) noexcept { if (this != &o) { reset(); move_from(o); } return *this; }

    bool Valid() const { return m_vm != nullptr; }
    const std::array<uint8_t, Consensus::RANDOMX_KEY_MAX_BYTES>& Key() const { return m_key; }

    // Single-shot hash (no pipelining).
    void Hash(const void* input, size_t inputSize, void* output) {
        randomx_calculate_hash(m_vm, input, inputSize, output);
    }
    // Pipelined hashing: First() begins a calculation; each Next() emits the hash
    // of the PREVIOUS input while beginning the next; Last() emits the final one.
    void HashFirst(const void* input, size_t inputSize) {
        randomx_calculate_hash_first(m_vm, input, inputSize);
    }
    void HashNext(const void* nextInput, size_t nextInputSize, void* output) {
        randomx_calculate_hash_next(m_vm, nextInput, nextInputSize, output);
    }
    void HashLast(void* output) {
        randomx_calculate_hash_last(m_vm, output);
    }

private:
    friend class RandomXManager;
    void reset() { if (m_vm) { randomx_destroy_vm(m_vm); m_vm = nullptr; } m_dataset.reset(); m_cache.reset(); }
    void move_from(MiningVM& o) {
        m_vm = o.m_vm; o.m_vm = nullptr;
        m_dataset = std::move(o.m_dataset);
        m_cache = std::move(o.m_cache);
        m_key = o.m_key;
    }

    randomx_vm* m_vm{nullptr};
    std::shared_ptr<randomx_dataset> m_dataset;   // pins dataset lifetime for m_vm
    std::shared_ptr<randomx_cache> m_cache;       // pins cache lifetime (light-mode fallback)
    std::array<uint8_t, Consensus::RANDOMX_KEY_MAX_BYTES> m_key{};
};

class RandomXManager {
public:
    static RandomXManager& Instance();

    void Init(bool useFastMode);
    void EnsureFastMode();
    void Shutdown();

    uint256 Hash(int height,
                 const CBlockIndex* pindexPrev,
                 const void* input, size_t inputSize);

    uint256 HashWithKey(const std::array<uint8_t, Consensus::RANDOMX_KEY_MAX_BYTES>& key,
                        const void* input, size_t inputSize);

    // Build (or reuse) the fast-mode dataset for `key` and hand back a fresh,
    // independent per-thread mining VM bound to it. Hashing on the returned VM is
    // lock-free. Call once per key epoch per thread (cheap no-op rebuild while the
    // key is unchanged); reuse the returned VM across nonces/templates until the
    // mining key changes. Returns an invalid MiningVM (Valid()==false) on failure.
    MiningVM AcquireMiningVM(const std::array<uint8_t, Consensus::RANDOMX_KEY_MAX_BYTES>& key);

    // True once fast (full-dataset) mode is active AND it was allocated with large
    // (huge) pages. When false in fast mode, RandomX fell back to regular pages and
    // hashrate is substantially lower — the miner logs a warning in that case.
    bool FastModeLargePages();

    // Set how many light validation caches (LRU depth) to retain. Clamped to
    // [RANDOMX_VALIDATION_CACHE_SLOTS_MIN, RANDOMX_VALIDATION_CACHE_SLOTS_MAX].
    // Higher values reduce cache rebuilds when validating headers that span many
    // key epochs; each slot costs ~256 MiB. This affects performance/memory ONLY —
    // never the hash output — so it is consensus-neutral and safe to tune freely.
    // Intended to be called once at startup (before validation begins).
    void SetValidationCacheSlots(size_t slots);

private:
    RandomXManager() = default;
    ~RandomXManager();
    RandomXManager(const RandomXManager&) = delete;
    RandomXManager& operator=(const RandomXManager&) = delete;

    void InitUnlocked(bool useFastMode);
    void EnsureFastModeUnlocked();
    void InitDatasetUnlocked();
    // Load `key` into the MINING resources. Returns true iff, on return,
    // m_current_key == key && m_key_loaded (i.e. the mining cache/dataset now
    // hold exactly the requested key). Returns false and leaves the manager
    // UNCHANGED (previous key still valid) if any allocation/initialization step
    // fails, so the caller must never hash against a key it did not load.
    bool EnsureKeyLoaded(const std::array<uint8_t, Consensus::RANDOMX_KEY_MAX_BYTES>& key);
    randomx_vm* CreateVMUnlocked();

    // Validation domain: return a light-mode (cache-only) RandomX cache
    // initialized for exactly `key`, from a small bounded LRU. Never allocates a
    // dataset. Returns nullptr on allocation failure (caller must fail closed).
    std::shared_ptr<randomx_cache> GetOrCreateValidationCacheUnlocked(
        const std::array<uint8_t, Consensus::RANDOMX_KEY_MAX_BYTES>& key);

    // secureJit enables W^X (RANDOMX_FLAG_SECURE) on the JIT buffer. It is a large
    // multi-thread throughput loss (mprotect serializes on the process-wide
    // mmap_lock), so it is used ONLY for the serialized validation domain, never
    // for mining. See the comment on the definition.
    static randomx_flags BuildFlags(bool useFastMode, bool useLargePages, bool secureJit);
    bool TryAllocResources(randomx_flags flags, bool useFastMode);

    static std::shared_ptr<randomx_cache> WrapCache(randomx_cache* c) {
        return std::shared_ptr<randomx_cache>(c, [](randomx_cache* p){ if (p) randomx_release_cache(p); });
    }
    static std::shared_ptr<randomx_dataset> WrapDataset(randomx_dataset* d) {
        return std::shared_ptr<randomx_dataset>(d, [](randomx_dataset* p){ if (p) randomx_release_dataset(p); });
    }

    std::mutex m_mutex;

    // ---- MINING domain (used only by AcquireMiningVM / the local miner) ----
    // The full-dataset fast path. The miner only ever loads the chain tip's key
    // (monotonic, not attacker-controlled), so a single current+prev is enough.
    // This domain is NEVER touched by the header-validation path, so a peer
    // cannot drive dataset (re)builds here.
    randomx_flags m_flags{RANDOMX_FLAG_DEFAULT};
    bool m_fast_mode{false};
    bool m_initialized{false};

    std::shared_ptr<randomx_cache> m_cache;
    std::shared_ptr<randomx_dataset> m_dataset;
    uint32_t m_key_generation{0};

    std::array<uint8_t, Consensus::RANDOMX_KEY_MAX_BYTES> m_current_key{};
    bool m_key_loaded{false};

    std::shared_ptr<randomx_cache> m_prev_cache;
    std::shared_ptr<randomx_dataset> m_prev_dataset;
    std::array<uint8_t, Consensus::RANDOMX_KEY_MAX_BYTES> m_prev_key{};
    bool m_prev_key_loaded{false};

    // ---- VALIDATION domain (used only by HashWithKey, the header/PoW path) ----
    // Header validation is attacker-reachable (peers can present headers from
    // arbitrary RandomX key epochs). To keep that path from (a) ever allocating
    // the ~2 GB dataset and (b) growing memory without bound, validation uses a
    // small LRU of LIGHT (cache-only, ~256 MiB each) caches — independent of the
    // mining domain above. Worst-case validation memory is bounded to
    // m_val_cache_slots * cache_size regardless of how many distinct epochs a peer
    // forces. Light-mode hashes are slower but consensus-identical.
    //
    // The depth is operator-tunable via SetValidationCacheSlots() / the
    // -rxvalidationcaches startup option. The DEFAULT is deliberately modest so a
    // normal node's baseline RAM is unchanged; the MAX bounds an operator against
    // accidentally requesting an absurd amount of memory. A larger value only
    // improves resistance to cross-epoch cache thrash and never affects the hash.
    static constexpr size_t RANDOMX_VALIDATION_CACHE_SLOTS_DEFAULT = 3;
    static constexpr size_t RANDOMX_VALIDATION_CACHE_SLOTS_MIN = 2;
    static constexpr size_t RANDOMX_VALIDATION_CACHE_SLOTS_MAX = 64;
    struct ValidationCacheEntry {
        std::array<uint8_t, Consensus::RANDOMX_KEY_MAX_BYTES> key;
        std::shared_ptr<randomx_cache> cache;
    };
    randomx_flags m_val_flags{RANDOMX_FLAG_DEFAULT};
    bool m_val_flags_init{false};
    size_t m_val_cache_slots{RANDOMX_VALIDATION_CACHE_SLOTS_DEFAULT};
    std::list<ValidationCacheEntry> m_val_caches; // most-recently-used at front
};

#endif // SHAICOIN_RANDOMX_MANAGER_H
