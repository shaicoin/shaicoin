// Copyright (c) 2024 The Shaicoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <randomx_manager.h>
#include <chain.h>
#include <logging.h>
#include <util/check.h>
#include <util/time.h>
#include <thread>
#include <chrono>

randomx_flags RandomXManager::BuildFlags(bool useFastMode, bool useLargePages)
{
    randomx_flags flags = randomx_get_flags() | RANDOMX_FLAG_V2;
    if (flags & RANDOMX_FLAG_JIT) {
        flags |= RANDOMX_FLAG_SECURE;
    }
    if (useLargePages) {
        flags |= RANDOMX_FLAG_LARGE_PAGES;
    }
    if (useFastMode) {
        flags |= RANDOMX_FLAG_FULL_MEM;
    }
    return flags;
}

bool RandomXManager::TryAllocResources(randomx_flags flags, bool useFastMode)
{
    m_cache.reset();
    m_dataset.reset();

    randomx_cache* cache = randomx_alloc_cache(flags);
    if (!cache) {
        return false;
    }
    m_cache = WrapCache(cache);

    if (useFastMode) {
        randomx_dataset* dataset = randomx_alloc_dataset(flags);
        if (!dataset) {
            m_cache.reset();
            return false;
        }
        m_dataset = WrapDataset(dataset);
    }

    m_flags = flags;
    return true;
}

void RandomXManager::InitDatasetUnlocked()
{
    if (!m_fast_mode || !m_dataset || !m_cache) return;

    // Capture raw pointers by value so the worker threads never touch manager
    // members (which may change under a concurrent rotation once we drop the lock
    // in the future); the shared_ptrs keep the buffers alive for the join below.
    randomx_dataset* dataset = m_dataset.get();
    randomx_cache* cache = m_cache.get();

    const auto itemCount = randomx_dataset_item_count();
    const unsigned int numThreads = std::max(1u, std::thread::hardware_concurrency());
    const auto perThread = itemCount / numThreads;

    std::vector<std::thread> threads;
    threads.reserve(numThreads);
    for (unsigned int i = 0; i < numThreads; ++i) {
        const auto start = i * perThread;
        const auto count = (i == numThreads - 1) ? (itemCount - start) : perThread;
        threads.emplace_back([dataset, cache, start, count]() {
            randomx_init_dataset(dataset, cache, start, count);
        });
    }
    for (auto& t : threads) t.join();
}

int GetRandomXKeyBlockHeight(int height)
{
    if (height < Consensus::RANDOMX_KEY_DELAY) return 0;
    return ((height - Consensus::RANDOMX_KEY_DELAY) / Consensus::RANDOMX_KEY_INTERVAL)
           * Consensus::RANDOMX_KEY_INTERVAL;
}

RandomXKeyContext LookupRandomXKeyContext(int height, const CBlockIndex* pindexPrev)
{
    RandomXKeyContext ctx;
    ctx.key_block_height = GetRandomXKeyBlockHeight(height);
    const CBlockIndex* pKeyIndex = pindexPrev;
    while (pKeyIndex && pKeyIndex->nHeight > ctx.key_block_height) {
        pKeyIndex = pKeyIndex->pprev;
    }
    if (pKeyIndex && pKeyIndex->nHeight == ctx.key_block_height) {
        ctx.key_block_hash = pKeyIndex->GetBlockHash();
        ctx.key_block_found = true;
    }
    ctx.key = DeriveRandomXKey(ctx.key_block_hash);
    return ctx;
}

std::array<uint8_t, Consensus::RANDOMX_KEY_MAX_BYTES> DeriveRandomXKey(const uint256& keyBlockHash)
{
    uint256 hashed = (HashWriter{} << keyBlockHash).GetSHA256();
    std::array<uint8_t, Consensus::RANDOMX_KEY_MAX_BYTES> key{};
    static_assert(Consensus::RANDOMX_KEY_MAX_BYTES == 60);
    static_assert(Consensus::RANDOMX_KEY_MAX_BYTES >= 32);
    std::copy(hashed.begin(), hashed.end(), key.begin());
    return key;
}

uint256 ComputeRandomXHash(const std::array<uint8_t, Consensus::RANDOMX_KEY_MAX_BYTES>& key,
                           const void* input, size_t inputSize)
{
    return RandomXManager::Instance().HashWithKey(key, input, inputSize);
}

RandomXManager& RandomXManager::Instance()
{
    static RandomXManager instance;
    return instance;
}

RandomXManager::~RandomXManager()
{
    Shutdown();
}

void RandomXManager::Init(bool useFastMode)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    InitUnlocked(useFastMode);
}

void RandomXManager::EnsureFastMode()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    EnsureFastModeUnlocked();
}

void RandomXManager::InitUnlocked(bool useFastMode)
{
    if (m_initialized) return;

    m_fast_mode = useFastMode;

    if (!TryAllocResources(BuildFlags(useFastMode, true), useFastMode)) {
        if (!TryAllocResources(BuildFlags(useFastMode, false), useFastMode)) {
            if (useFastMode) {
                m_fast_mode = false;
                if (!TryAllocResources(BuildFlags(false, true), false) &&
                    !TryAllocResources(BuildFlags(false, false), false)) {
                    LogError("RandomX: Failed to allocate cache\n");
                    return;
                }
                LogPrintLevel_(BCLog::RANDOMX, BCLog::Level::Warning, false,
                               "RandomX: Failed to allocate dataset, falling back to light mode\n");
            } else {
                LogError("RandomX: Failed to allocate cache\n");
                return;
            }
        } else if (useFastMode) {
            LogPrintLevel_(BCLog::RANDOMX, BCLog::Level::Warning, false,
                           "RandomX: huge pages unavailable for dataset, using regular pages\n");
        }
    }

    m_initialized = true;
    LogDebug(BCLog::RANDOMX,
             "RandomX v2 initialized (%s mode, jit=%d, secure=%d, huge_pages=%d, key_interval=%d, key_delay=%d, key_bytes=%d)\n",
             m_fast_mode ? "fast" : "light",
             (m_flags & RANDOMX_FLAG_JIT) ? 1 : 0,
             (m_flags & RANDOMX_FLAG_SECURE) ? 1 : 0,
             (m_flags & RANDOMX_FLAG_LARGE_PAGES) ? 1 : 0,
             Consensus::RANDOMX_KEY_INTERVAL,
             Consensus::RANDOMX_KEY_DELAY,
             static_cast<int>(Consensus::RANDOMX_KEY_MAX_BYTES));
}

void RandomXManager::EnsureFastModeUnlocked()
{
    if (m_initialized && m_fast_mode) return;

    if (!m_initialized) {
        InitUnlocked(true);
        return;
    }

    const auto saved_key = m_current_key;
    const bool had_key = m_key_loaded;

    // Build the fast-mode cache+dataset off to the side, committing only once both
    // succeed (mirrors EnsureKeyLoaded's commit-on-success discipline).
    randomx_flags new_flags = BuildFlags(true, true);
    randomx_cache* nc = randomx_alloc_cache(new_flags);
    randomx_dataset* nd = nc ? randomx_alloc_dataset(new_flags) : nullptr;
    if (!nc || !nd) {
        if (nc) randomx_release_cache(nc);
        if (nd) randomx_release_dataset(nd);
        new_flags = BuildFlags(true, false);
        nc = randomx_alloc_cache(new_flags);
        nd = nc ? randomx_alloc_dataset(new_flags) : nullptr;
        if (nc && nd) {
            LogPrintLevel_(BCLog::RANDOMX, BCLog::Level::Warning, false,
                           "RandomX: huge pages unavailable, using regular pages for mining\n");
        }
    }
    if (!nc || !nd) {
        if (nc) randomx_release_cache(nc);
        if (nd) randomx_release_dataset(nd);
        m_fast_mode = false;
        LogError("RandomX: Failed to upgrade to fast mode\n");
        return;
    }

    // Demote the current (light) buffers to prev; assigning shared_ptrs releases
    // whatever prev held before (refcount drop). Install the new fast buffers.
    m_prev_cache = m_cache;
    m_prev_dataset = m_dataset;
    m_prev_key = m_current_key;
    m_prev_key_loaded = m_key_loaded;

    m_cache = WrapCache(nc);
    m_dataset = WrapDataset(nd);
    m_flags = new_flags;
    m_fast_mode = true;

    if (had_key) {
        randomx_init_cache(m_cache.get(), saved_key.data(), saved_key.size());
        InitDatasetUnlocked();
        m_current_key = saved_key;
        m_key_loaded = true;
    }

    ++m_key_generation;
    LogDebug(BCLog::RANDOMX,
             "RandomX upgraded to fast mode (huge_pages=%d, generation=%u)\n",
             (m_flags & RANDOMX_FLAG_LARGE_PAGES) ? 1 : 0,
             m_key_generation);
}

void RandomXManager::Shutdown()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    // Release the validation-domain light caches. This is independent of the
    // mining domain's m_initialized flag (a validation-only node never sets it).
    // Any cache still referenced by a live thread_local validation VM survives
    // until that thread exits.
    m_val_caches.clear();

    if (!m_initialized) return;

    // shared_ptr releases the manager's reference; any buffer still referenced by
    // an outstanding MiningVM (or an in-flight VM) survives until that holder is
    // destroyed, so this is safe even while miner threads are winding down.
    m_dataset.reset();
    m_cache.reset();
    m_prev_dataset.reset();
    m_prev_cache.reset();

    m_key_loaded = false;
    m_prev_key_loaded = false;
    m_initialized = false;
}

bool RandomXManager::EnsureKeyLoaded(const std::array<uint8_t, Consensus::RANDOMX_KEY_MAX_BYTES>& key)
{
    if (m_key_loaded && m_current_key == key) return true;
    if (m_prev_key_loaded && m_prev_key == key) {
        std::swap(m_cache, m_prev_cache);
        std::swap(m_dataset, m_prev_dataset);
        std::swap(m_current_key, m_prev_key);
        std::swap(m_key_loaded, m_prev_key_loaded);

        ++m_key_generation;
        LogDebug(BCLog::RANDOMX, "RandomX key restored from previous cache (generation=%u)\n", m_key_generation);
        return true;
    }

    const auto load_start = std::chrono::steady_clock::now();

    if (m_key_loaded) {
        // Rotate to a new key. Build the new cache (and dataset in fast mode) into
        // LOCALS and only commit once every step has succeeded. A mid-rotation
        // allocation failure returns false leaving the manager UNCHANGED (current
        // key still valid, no dangling/aliased buffers, no uninitialized cache).
        // The caller MUST treat false as "requested key not loaded" and fail
        // closed — it must not hash, because the still-loaded key is a DIFFERENT
        // key and hashing with it would produce a wrong-but-non-null result (a
        // consensus fork: this node would judge blocks against the wrong key).
        randomx_cache* nc = randomx_alloc_cache(m_flags);
        if (!nc) {
            LogError("RandomX: Failed to allocate cache during key rotation\n");
            return false;
        }
        randomx_dataset* nd = nullptr;
        if (m_fast_mode) {
            nd = randomx_alloc_dataset(m_flags);
            if (!nd) {
                randomx_release_cache(nc);
                LogError("RandomX: Failed to allocate dataset during key rotation\n");
                return false;
            }
        }

        // Initialize the fresh cache for the requested key before it is reachable.
        randomx_init_cache(nc, key.data(), key.size());

        // Commit. Assigning shared_ptrs drops the prior prev refs (auto-release).
        m_prev_cache = m_cache;
        m_prev_dataset = m_dataset;
        m_prev_key = m_current_key;
        m_prev_key_loaded = true;

        m_cache = WrapCache(nc);
        m_dataset = nd ? WrapDataset(nd) : nullptr;

        if (m_fast_mode && m_dataset) {
            InitDatasetUnlocked();
        }

        m_current_key = key;
        m_key_loaded = true;
        ++m_key_generation;

        const auto rot_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - load_start).count();
        LogDebug(BCLog::RANDOMX,
                       "RandomX key rotated (generation=%u, mode=%s, init_ms=%lld)\n",
                       m_key_generation, m_fast_mode ? "fast" : "light", rot_ms);
        return true;
    }

    // First key load: m_cache was already allocated by InitUnlocked (non-null; the
    // callers check before reaching here).
    randomx_init_cache(m_cache.get(), key.data(), key.size());

    if (m_fast_mode && m_dataset) {
        InitDatasetUnlocked();
    }

    m_current_key = key;
    m_key_loaded = true;
    ++m_key_generation;

    const auto load_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - load_start).count();
    LogDebug(BCLog::RANDOMX,
                   "RandomX key loaded (generation=%u, mode=%s, init_ms=%lld)\n",
                   m_key_generation, m_fast_mode ? "fast" : "light", load_ms);
    return true;
}

randomx_vm* RandomXManager::CreateVMUnlocked()
{
    const auto make = [&](randomx_flags vm_flags) -> randomx_vm* {
        if (m_fast_mode && m_dataset) {
            return randomx_create_vm(vm_flags, nullptr, m_dataset.get());
        }
        if (m_cache) {
            return randomx_create_vm(vm_flags, m_cache.get(), nullptr);
        }
        return nullptr;
    };

    randomx_vm* vm = make(m_flags);
    if (!vm && (m_flags & RANDOMX_FLAG_LARGE_PAGES)) {
        const randomx_flags fallback_flags = static_cast<randomx_flags>(
            static_cast<int>(m_flags) & ~static_cast<int>(RANDOMX_FLAG_LARGE_PAGES));
        vm = make(fallback_flags);
        if (vm) {
            LogPrintLevel_(BCLog::RANDOMX, BCLog::Level::Warning, false,
                           "RandomX VM using regular pages for scratchpad\n");
        }
    }
    return vm;
}

uint256 RandomXManager::Hash(int height,
                             const CBlockIndex* pindexPrev,
                             const void* input, size_t inputSize)
{
    const RandomXKeyContext ctx = LookupRandomXKeyContext(height, pindexPrev);
    if (!ctx.key_block_found) {
        LogPrintLevel_(BCLog::RANDOMX, BCLog::Level::Warning, false,
                       "RandomX Hash: missing key block at height %d (expected %d)\n",
                       height, ctx.key_block_height);
        return uint256{};
    }
    return HashWithKey(ctx.key, input, inputSize);
}

std::shared_ptr<randomx_cache> RandomXManager::GetOrCreateValidationCacheUnlocked(
    const std::array<uint8_t, Consensus::RANDOMX_KEY_MAX_BYTES>& key)
{
    // Reuse an already-initialized cache for this key if we have one (LRU hit),
    // moving it to the front as most-recently-used.
    for (auto it = m_val_caches.begin(); it != m_val_caches.end(); ++it) {
        if (it->key == key) {
            if (it != m_val_caches.begin()) {
                m_val_caches.splice(m_val_caches.begin(), m_val_caches, it);
            }
            return m_val_caches.front().cache;
        }
    }

    // Miss: allocate a fresh LIGHT (cache-only) cache and initialize it for
    // exactly this key. We never allocate a dataset here, so this path can never
    // build the ~2 GB full-memory buffer no matter which/how many epochs a peer
    // asks us to validate.
    const auto load_start = std::chrono::steady_clock::now();
    randomx_cache* c = randomx_alloc_cache(m_val_flags);
    if (!c) {
        LogError("RandomX: Failed to allocate validation cache\n");
        return nullptr; // caller fails closed
    }
    auto sp = WrapCache(c);
    randomx_init_cache(c, key.data(), key.size());

    m_val_caches.push_front({key, sp});
    // Bound memory: evicting drops the shared_ptr; the cache is freed once no VM
    // still references it. Worst-case resident set is m_val_cache_slots * cache_size.
    while (m_val_caches.size() > m_val_cache_slots) {
        m_val_caches.pop_back();
    }

    const auto init_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - load_start).count();
    LogDebug(BCLog::RANDOMX,
             "RandomX validation cache loaded (light, slots=%zu, init_ms=%lld)\n",
             m_val_caches.size(), init_ms);
    return sp;
}

uint256 RandomXManager::HashWithKey(const std::array<uint8_t, Consensus::RANDOMX_KEY_MAX_BYTES>& key,
                                    const void* input, size_t inputSize)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    // The header/PoW validation path is attacker-reachable and must be isolated
    // from the mining (fast/full-dataset) domain: it always hashes in LIGHT mode
    // against a per-key cache drawn from a small bounded LRU. This guarantees we
    // (1) hash with EXACTLY the requested key or fail closed (returning null,
    // which the pow.cpp callers reject) — never with a stale/wrong key — and
    // (2) never allocate the ~2 GB dataset, so a peer feeding us headers from
    // many key epochs cannot exhaust memory or thrash a shared dataset.
    if (!m_val_flags_init) {
        m_val_flags = BuildFlags(/*useFastMode=*/false, /*useLargePages=*/false);
        m_val_flags_init = true;
    }

    std::shared_ptr<randomx_cache> cache = GetOrCreateValidationCacheUnlocked(key);
    if (!cache) {
        // Could not bring up a cache for this key. Fail closed: a null hash is
        // treated as a verification failure by CheckProofOfWorkRandomX*.
        return uint256{};
    }

    // Per-thread light VM for the validation path. Its RAII destructor runs on
    // thread exit and frees only the VM's own scratchpad (never the cache), so it
    // is safe regardless of which cache the LRU currently holds.
    struct TlsVM {
        randomx_vm* vm{nullptr};
        ~TlsVM() { if (vm) randomx_destroy_vm(vm); }
    };
    thread_local TlsVM tls;

    if (!tls.vm) {
        tls.vm = randomx_create_vm(m_val_flags, cache.get(), nullptr);
        if (!tls.vm) {
            LogError("RandomX: Failed to create validation VM\n");
            return uint256{}; // fail closed
        }
    } else {
        // Re-point the persistent VM at the cache selected for THIS key. We always
        // (re)bind before hashing so the VM can never hash `input` against a cache
        // for a different key — the LRU may have handed us a different entry than
        // last call, and a raw-pointer comparison could alias a freed-then-reused
        // cache (ABA). Rebinding is cheap relative to a hash and always correct.
        randomx_vm_set_cache(tls.vm, cache.get());
    }

    uint256 result;
    randomx_calculate_hash(tls.vm, input, inputSize, result.begin());
    return result;
}

bool RandomXManager::FastModeLargePages()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_fast_mode && (m_flags & RANDOMX_FLAG_LARGE_PAGES);
}

void RandomXManager::SetValidationCacheSlots(size_t slots)
{
    if (slots < RANDOMX_VALIDATION_CACHE_SLOTS_MIN) slots = RANDOMX_VALIDATION_CACHE_SLOTS_MIN;
    if (slots > RANDOMX_VALIDATION_CACHE_SLOTS_MAX) slots = RANDOMX_VALIDATION_CACHE_SLOTS_MAX;

    std::lock_guard<std::mutex> lock(m_mutex);
    m_val_cache_slots = slots;
    // Trim immediately if the new bound is smaller than what we currently hold.
    while (m_val_caches.size() > m_val_cache_slots) {
        m_val_caches.pop_back();
    }
    LogDebug(BCLog::RANDOMX, "RandomX validation cache depth set to %zu (~%zu MiB max)\n",
             m_val_cache_slots, m_val_cache_slots * 256);
}

MiningVM RandomXManager::AcquireMiningVM(const std::array<uint8_t, Consensus::RANDOMX_KEY_MAX_BYTES>& key)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    // Mining wants the full-dataset (fast) path. Upgrade once; no-op thereafter.
    EnsureFastModeUnlocked();
    if (!m_initialized) {
        InitUnlocked(true);
    }
    if (!m_initialized || !m_cache) {
        LogError("RandomX: AcquireMiningVM before successful initialization\n");
        return MiningVM{};
    }

    // Fail closed if we could not load exactly the requested key. Returning an
    // invalid VM here (rather than one bound to a stale key) stops the miner from
    // producing blocks against the wrong RandomX key — which the network would
    // reject — and keeps MiningVM::Key() honest.
    if (!EnsureKeyLoaded(key) || !m_key_loaded || m_current_key != key) {
        LogError("RandomX: could not load requested key for mining VM\n");
        return MiningVM{};
    }

    MiningVM handle;
    // shared_ptr copies pin the cache/dataset for the whole life of this VM, so a
    // later mining-key rotation (another thread re-acquiring at a new epoch) cannot
    // free the buffers this miner is hashing against — the returned VM hashes with
    // NO lock held. The validation path is a separate domain and never aliases
    // these buffers at all.
    handle.m_dataset = m_dataset;
    handle.m_cache = m_cache;
    handle.m_key = key;
    handle.m_vm = CreateVMUnlocked();
    if (!handle.m_vm) {
        LogError("RandomX: Failed to create mining VM\n");
        return MiningVM{};
    }
    return handle;
}
