// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/chainstate.h>

#include <arith_uint256.h>
#include <chain.h>
#include <coins.h>
#include <consensus/params.h>
#include <kernel/caches.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <pow.h>
#include <sync.h>
#include <threadsafety.h>
#include <tinyformat.h>
#include <txdb.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/signalinterrupt.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>

#include <algorithm>
#include <cassert>
#include <vector>

using kernel::CacheSizes;

namespace node {

// An older v4 node could accept a timestamp at or below its direct parent.
// That block may already be the tip recorded in the coins database when the
// node is upgraded, so it will not pass through header acceptance again. Find
// the first such indexed block and use the normal invalidation path to undo its
// active descendants, mark the bad branch failed, and select a valid chain.
static ChainstateLoadResult RepairPostForkTimestampRollback(ChainstateManager& chainman)
{
    bool repaired{false};

    while (!chainman.m_interrupt) {
        CBlockIndex* bad_block{WITH_LOCK(cs_main, {
            CBlockIndex* earliest_bad{nullptr};
            for (auto& [_, block_index] : chainman.BlockIndex()) {
                if (block_index.pprev == nullptr || block_index.nStatus & BLOCK_FAILED_MASK) {
                    continue;
                }
                if (!IsPostForkTimestampMonotonic(
                        block_index.GetBlockHeader(), *block_index.pprev, chainman.GetConsensus())) {
                    if (earliest_bad == nullptr || block_index.nHeight < earliest_bad->nHeight) {
                        earliest_bad = &block_index;
                    }
                }
            }
            return earliest_bad;
        })};

        if (bad_block == nullptr) {
            break;
        }

        // A wiped chainstate has no active UTXO tip to unwind. Its block
        // activation will run the equivalent check in ConnectBlock().
        if (!WITH_LOCK(cs_main, return chainman.ActiveTip() != nullptr)) {
            break;
        }

        LogPrintf("Consensus repair: invalidating non-monotonic v4 timestamp block=%s height=%d time=%u parent=%s parent_time=%u\n",
                  bad_block->GetBlockHash().ToString(), bad_block->nHeight, bad_block->GetBlockTime(),
                  bad_block->pprev->GetBlockHash().ToString(), bad_block->pprev->GetBlockTime());

        BlockValidationState state;
        if (!chainman.ActiveChainstate().InvalidateBlock(state, bad_block)) {
            return {ChainstateLoadStatus::FAILURE,
                    Untranslated(strprintf("Unable to roll back invalid v4 block %s: %s",
                                           bad_block->GetBlockHash().ToString(), state.ToString()))};
        }
        repaired = true;
    }

    if (chainman.m_interrupt) {
        return {ChainstateLoadStatus::INTERRUPTED, {}};
    }
    if (!repaired) {
        return {ChainstateLoadStatus::SUCCESS, {}};
    }

    // InvalidateBlock() leaves the chain at the last valid ancestor. Immediately
    // consider the remaining candidates, then persist both the UTXO rollback and
    // BLOCK_FAILED_* flags so a restart cannot restore the rejected branch.
    BlockValidationState state;
    Chainstate& active_chainstate{chainman.ActiveChainstate()};
    if (!active_chainstate.ActivateBestChain(state)) {
        return {ChainstateLoadStatus::FAILURE,
                Untranslated(strprintf("Unable to activate a valid chain after v4 timestamp rollback: %s", state.ToString()))};
    }
    if (!active_chainstate.FlushStateToDisk(state, FlushStateMode::ALWAYS)) {
        return {ChainstateLoadStatus::FAILURE,
                Untranslated(strprintf("Unable to persist v4 timestamp rollback: %s", state.ToString()))};
    }

    return {ChainstateLoadStatus::SUCCESS, {}};
}

// Complete initialization of chainstates after the initial call has been made
// to ChainstateManager::InitializeChainstate().
static ChainstateLoadResult CompleteChainstateInitialization(
    ChainstateManager& chainman,
    const ChainstateLoadOptions& options) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    if (chainman.m_interrupt) return {ChainstateLoadStatus::INTERRUPTED, {}};

    // LoadBlockIndex will load m_have_pruned if we've ever removed a
    // block file from disk.
    // Note that it also sets m_blockfiles_indexed based on the disk flag!
    if (!chainman.LoadBlockIndex()) {
        if (chainman.m_interrupt) return {ChainstateLoadStatus::INTERRUPTED, {}};
        return {ChainstateLoadStatus::FAILURE, _("Error loading block database")};
    }

    if (!chainman.BlockIndex().empty() &&
            !chainman.m_blockman.LookupBlockIndex(chainman.GetConsensus().hashGenesisBlock)) {
        // If the loaded chain has a wrong genesis, bail out immediately
        // (we're likely using a testnet datadir, or the other way around).
        return {ChainstateLoadStatus::FAILURE_INCOMPATIBLE_DB, _("Incorrect or no genesis block found. Wrong datadir for network?")};
    }

    // Check for changed -prune state.  What we are concerned about is a user who has pruned blocks
    // in the past, but is now trying to run unpruned.
    if (chainman.m_blockman.m_have_pruned && !options.prune) {
        return {ChainstateLoadStatus::FAILURE, _("You need to rebuild the database using -reindex to go back to unpruned mode.  This will redownload the entire blockchain")};
    }

    // At this point blocktree args are consistent with what's on disk.
    // If we're not mid-reindex (based on disk + args), add a genesis block on disk
    // (otherwise we use the one already on disk).
    // This is called again in ImportBlocks after the reindex completes.
    if (chainman.m_blockman.m_blockfiles_indexed && !chainman.ActiveChainstate().LoadGenesisBlock()) {
        return {ChainstateLoadStatus::FAILURE, _("Error initializing block database")};
    }

    auto is_coinsview_empty = [&](Chainstate* chainstate) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        return options.wipe_chainstate_db || chainstate->CoinsTip().GetBestBlock().IsNull();
    };

    assert(chainman.m_total_coinstip_cache > 0);
    assert(chainman.m_total_coinsdb_cache > 0);

    // If running with multiple chainstates, limit the cache sizes with a
    // discount factor. If discounted the actual cache size will be
    // recalculated by `chainman.MaybeRebalanceCaches()`. The discount factor
    // is conservatively chosen such that the sum of the caches does not exceed
    // the allowable amount during this temporary initialization state.
    double init_cache_fraction = chainman.GetAll().size() > 1 ? 0.2 : 1.0;

    // At this point we're either in reindex or we've loaded a useful
    // block tree into BlockIndex()!

    for (Chainstate* chainstate : chainman.GetAll()) {
        LogPrintf("Initializing chainstate %s\n", chainstate->ToString());

        try {
            chainstate->InitCoinsDB(
                /*cache_size_bytes=*/chainman.m_total_coinsdb_cache * init_cache_fraction,
                /*in_memory=*/options.coins_db_in_memory,
                /*should_wipe=*/options.wipe_chainstate_db);
        } catch (dbwrapper_error& err) {
            LogError("%s\n", err.what());
            return {ChainstateLoadStatus::FAILURE, _("Error opening coins database")};
        }

        if (options.coins_error_cb) {
            chainstate->CoinsErrorCatcher().AddReadErrCallback(options.coins_error_cb);
        }

        // Refuse to load unsupported database format.
        // This is a no-op if we cleared the coinsviewdb with -reindex or -reindex-chainstate
        if (chainstate->CoinsDB().NeedsUpgrade()) {
            return {ChainstateLoadStatus::FAILURE_INCOMPATIBLE_DB, _("Unsupported chainstate database format found. "
                                                                     "Please restart with -reindex-chainstate. This will "
                                                                     "rebuild the chainstate database.")};
        }

        // ReplayBlocks is a no-op if we cleared the coinsviewdb with -reindex or -reindex-chainstate
        if (!chainstate->ReplayBlocks()) {
            return {ChainstateLoadStatus::FAILURE, _("Unable to replay blocks. You will need to rebuild the database using -reindex-chainstate.")};
        }

        // The on-disk coinsdb is now in a good state, create the cache
        chainstate->InitCoinsCache(chainman.m_total_coinstip_cache * init_cache_fraction);
        assert(chainstate->CanFlushToDisk());

        if (!is_coinsview_empty(chainstate)) {
            // LoadChainTip initializes the chain based on CoinsTip()'s best block
            if (!chainstate->LoadChainTip()) {
                return {ChainstateLoadStatus::FAILURE, _("Error initializing block database")};
            }
            assert(chainstate->m_chain.Tip() != nullptr);
        }
    }

    auto chainstates{chainman.GetAll()};
    if (std::any_of(chainstates.begin(), chainstates.end(),
                    [](const Chainstate* cs) EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return cs->NeedsRedownload(); })) {
        return {ChainstateLoadStatus::FAILURE, strprintf(_("Witness data for blocks after height %d requires validation. Please restart with -reindex."),
                                                         chainman.GetConsensus().SegwitHeight)};
    };

    // Now that chainstates are loaded and we're able to flush to
    // disk, rebalance the coins caches to desired levels based
    // on the condition of each chainstate.
    chainman.MaybeRebalanceCaches();

    return {ChainstateLoadStatus::SUCCESS, {}};
}

ChainstateLoadResult LoadChainstate(ChainstateManager& chainman, const CacheSizes& cache_sizes,
                                    const ChainstateLoadOptions& options)
{
    if (!chainman.AssumedValidBlock().IsNull()) {
        LogPrintf("Assuming ancestors of block %s have valid signatures.\n", chainman.AssumedValidBlock().GetHex());
    } else {
        LogPrintf("Validating signatures for all blocks.\n");
    }
    LogPrintf("Setting nMinimumChainWork=%s\n", chainman.MinimumChainWork().GetHex());
    if (chainman.MinimumChainWork() < UintToArith256(chainman.GetConsensus().nMinimumChainWork)) {
        LogPrintf("Warning: nMinimumChainWork set below default value of %s\n", chainman.GetConsensus().nMinimumChainWork.GetHex());
    }
    if (chainman.m_blockman.GetPruneTarget() == BlockManager::PRUNE_TARGET_MANUAL) {
        LogPrintf("Block pruning enabled.  Use RPC call pruneblockchain(height) to manually prune block and undo files.\n");
    } else if (chainman.m_blockman.GetPruneTarget()) {
        LogPrintf("Prune configured to target %u MiB on disk for block and undo files.\n", chainman.m_blockman.GetPruneTarget() / 1024 / 1024);
    }

    {
        LOCK(cs_main);

        chainman.m_total_coinstip_cache = cache_sizes.coins;
        chainman.m_total_coinsdb_cache = cache_sizes.coins_db;

        // Load the fully validated chainstate.
        chainman.InitializeChainstate(options.mempool);

        // Load a chain created from a UTXO snapshot, if any exist.
        bool has_snapshot = chainman.DetectSnapshotChainstate();

        if (has_snapshot && options.wipe_chainstate_db) {
            LogPrintf("[snapshot] deleting snapshot chainstate due to reindexing\n");
            if (!chainman.DeleteSnapshotChainstate()) {
                return {ChainstateLoadStatus::FAILURE_FATAL, Untranslated("Couldn't remove snapshot chainstate.")};
            }
        }

        auto [init_status, init_error] = CompleteChainstateInitialization(chainman, options);
        if (init_status != ChainstateLoadStatus::SUCCESS) {
            return {init_status, init_error};
        }
    }

    // This must run without cs_main: InvalidateBlock() takes its own locks
    // while disconnecting the persisted invalid branch.
    auto [repair_status, repair_error] = RepairPostForkTimestampRollback(chainman);
    if (repair_status != ChainstateLoadStatus::SUCCESS) {
        return {repair_status, repair_error};
    }

    LOCK(cs_main);

    // If a snapshot chainstate was fully validated by a background chainstate during
    // the last run, detect it here and clean up the now-unneeded background
    // chainstate.
    //
    // Why is this cleanup done here (on subsequent restart) and not just when the
    // snapshot is actually validated? Because this entails unusual
    // filesystem operations to move leveldb data directories around, and that seems
    // too risky to do in the middle of normal runtime.
    auto snapshot_completion = chainman.MaybeCompleteSnapshotValidation();

    if (snapshot_completion == SnapshotCompletionResult::SKIPPED) {
        // do nothing; expected case
    } else if (snapshot_completion == SnapshotCompletionResult::SUCCESS) {
        LogPrintf("[snapshot] cleaning up unneeded background chainstate, then reinitializing\n");
        if (!chainman.ValidatedSnapshotCleanup()) {
            return {ChainstateLoadStatus::FAILURE_FATAL, Untranslated("Background chainstate cleanup failed unexpectedly.")};
        }

        // Because ValidatedSnapshotCleanup() has torn down chainstates with
        // ChainstateManager::ResetChainstates(), reinitialize them here without
        // duplicating the blockindex work above.
        assert(chainman.GetAll().empty());
        assert(!chainman.IsSnapshotActive());
        assert(!chainman.IsSnapshotValidated());

        chainman.InitializeChainstate(options.mempool);

        // A reload of the block index is required to recompute setBlockIndexCandidates
        // for the fully validated chainstate.
        chainman.ActiveChainstate().ClearBlockIndexCandidates();

        auto [init_status, init_error] = CompleteChainstateInitialization(chainman, options);
        if (init_status != ChainstateLoadStatus::SUCCESS) {
            return {init_status, init_error};
        }
    } else {
        return {ChainstateLoadStatus::FAILURE_FATAL, _(
           "UTXO snapshot failed to validate. "
           "Restart to resume normal initial block download, or try loading a different snapshot.")};
    }

    return {ChainstateLoadStatus::SUCCESS, {}};
}

ChainstateLoadResult VerifyLoadedChainstate(ChainstateManager& chainman, const ChainstateLoadOptions& options)
{
    auto is_coinsview_empty = [&](Chainstate* chainstate) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        return options.wipe_chainstate_db || chainstate->CoinsTip().GetBestBlock().IsNull();
    };

    LOCK(cs_main);

    for (Chainstate* chainstate : chainman.GetAll()) {
        if (!is_coinsview_empty(chainstate)) {
            const CBlockIndex* tip = chainstate->m_chain.Tip();
            if (tip && tip->nTime > GetTime() + MAX_FUTURE_BLOCK_TIME) {
                return {ChainstateLoadStatus::FAILURE, _("The block database contains a block which appears to be from the future. "
                                                         "This may be due to your computer's date and time being set incorrectly. "
                                                         "Only rebuild the block database if you are sure that your computer's date and time are correct")};
            }

            VerifyDBResult result = CVerifyDB(chainman.GetNotifications()).VerifyDB(
                *chainstate, chainman.GetConsensus(), chainstate->CoinsDB(),
                options.check_level,
                options.check_blocks);
            switch (result) {
            case VerifyDBResult::SUCCESS:
            case VerifyDBResult::SKIPPED_MISSING_BLOCKS:
                break;
            case VerifyDBResult::INTERRUPTED:
                return {ChainstateLoadStatus::INTERRUPTED, _("Block verification was interrupted")};
            case VerifyDBResult::CORRUPTED_BLOCK_DB:
                return {ChainstateLoadStatus::FAILURE, _("Corrupted block database detected")};
            case VerifyDBResult::SKIPPED_L3_CHECKS:
                if (options.require_full_verification) {
                    return {ChainstateLoadStatus::FAILURE_INSUFFICIENT_DBCACHE, _("Insufficient dbcache for block verification")};
                }
                break;
            } // no default case, so the compiler can warn about missing cases
        }
    }

    return {ChainstateLoadStatus::SUCCESS, {}};
}
} // namespace node
