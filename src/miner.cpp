// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner.h"
#include <node/miner.h>

#include <policy/feerate.h>
#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "hash.h"
#include "net.h"
#include "policy/policy.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "txmempool.h"
#include <util/moneystr.h>
#include "validationinterface.h"

#include <logging.h>
#include <common/system.h>
#include <util/threadnames.h>
#include <util/thread.h>
#include <util/batchpriority.h>
#include <validation.h>
#include <util/signalinterrupt.h>
#include <randomx_manager.h>
#include <shaicoin_ext_payload.h>
#include <primitives/legacy_block.h>

#include <common/args.h>
#include <queue>
#include <random>
#include <span>

#if defined(__APPLE__)
#include <pthread/qos.h>
#endif
#ifndef WIN32
#include <sys/resource.h>
#endif

using namespace std;
using node::BlockAssembler;
using node::CBlockTemplate;
using node::UpdateTime;

bool legacy_miner = false;
bool make_genesis = false; // remove this and any code it touches
// also change where pblock is set

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.version = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << nBits << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();

    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Proof-of-work is essentially one-CPU-one-vote";
    const CScript genesisOutputScript = CScript() << ParseHex("046f93d36211501191a15cddf852fed215cd16135c2484832f801f3512e60b3d8b69be5a6b181ad7f18062bdd2d2906a2c90245476f74fffc9ab7af5780f55344b") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

//////////////////////////////////////////////////////////////////////////////
//
// ShaicoinMiner
//
//////////////////////////////////////////////////////////////////////////////
//             ___
//          .-' \\".
//         /`    ;--:
//        |     (  (_)==
//        |_ ._ '.__.;
//        \_/`--_---_(
//         (`--(./-\.)
//         `|     _\ |
//          | \  __ /
//         /|  '.__/
//      .'` \     |_
//           '-__ / `-
std::atomic<bool> shouldMine{};
std::atomic<uint64_t> total_hashes{0};
std::atomic<bool> g_mine_require_peers{true};

void StopMining()
{
    shouldMine = false;
    LogDebug(BCLog::MINING, "StopMining: signal sent to miner threads\n");
}

// Run mining at a reduced scheduling priority so that networking, RPC and
// block-validation threads (which serve syncing peers) always win the CPU.
// This keeps a busy miner from starving its own node, which matters most when
// the miner and a syncing peer share a single machine.
static void LowerMinerThreadPriority()
{
#if defined(__APPLE__)
    pthread_set_qos_class_self_np(QOS_CLASS_UTILITY, 0);
#elif !defined(WIN32)
    setpriority(PRIO_PROCESS, 0, 10);
#endif
    ScheduleBatchPriority();
}

static constexpr auto MINER_TEMPLATE_REFRESH = std::chrono::seconds(5);

// Lock-free, pipelined RandomX nonce search. The mining VM is owned by the caller
// (one per thread) and shares a single read-only dataset with the other threads,
// so N mining threads scan on N cores with NO lock contention — the key to
// multi-core throughput. Pipelining (hash_first/hash_next) overlaps each hash's
// dataset reads with the previous hash's finalization for a further few %.
//
// The pipelined API emits the PREVIOUS input's hash from each HashNext() call, so
// `pending` always trails the input currently being prepared. `pblock->nNonce` is
// restored to the winning nonce before returning true.
bool static ScanHashRandomX(CBlockHeader *pblock, uint32_t& nNonce, uint256 *phash,
                            ChainstateManager& chainman, MiningVM& vm) {
    const auto scan_start = std::chrono::steady_clock::now();
    const arith_uint256 target = arith_uint256().SetCompact(pblock->nBits);

    // Prime the pipeline with the first nonce's preimage.
    uint32_t pending = nNonce;
    pblock->nNonce = pending;
    uint256 Hprime = RandomXPreimageHash(*pblock);
    vm.HashFirst(Hprime.data(), Hprime.size());

    while (shouldMine) {
        const uint32_t next = pending + 1;
        pblock->nNonce = next;
        uint256 Hnext = RandomXPreimageHash(*pblock);

        uint256 R;
        vm.HashNext(Hnext.data(), Hnext.size(), R.begin());   // R == hash(pending)
        total_hashes++;

        // A null hash means the RandomX layer failed to compute (alloc/init
        // failure); it must not be treated as a winning solution (0 <= target),
        // otherwise the miner would emit a block with no valid proof of work that
        // our own validator (and every peer) now rejects.
        if (!R.IsNull() && UintToArith256(R) <= target) {
            *phash = R;
            nNonce = pending;          // report the winning nonce
            pblock->nNonce = pending;  // restore the header to the winner
            return true;
        }

        pending = next;

        if ((pending & 0xFFF) == 0) {
            {
                LOCK(cs_main);
                if (pblock->hashPrevBlock != chainman.ActiveTip()->GetBlockHash()) {
                    nNonce = pending;
                    return false;
                }
            }
            if (std::chrono::steady_clock::now() - scan_start >= MINER_TEMPLATE_REFRESH) {
                nNonce = pending;
                return false;
            }
        }
    }

    nNonce = pending;
    return false;
}

bool static ScanHashLegacy(CBlock *pblock, uint32_t& nNonce, uint256 *phash,
                           ChainstateManager& chainman, CLegacyBlockHeader& outHeader) {
    const auto scan_start = std::chrono::steady_clock::now();
    while (shouldMine) {
        nNonce++;

        CLegacyBlockHeader lh;
        lh.nVersion = pblock->nVersion;
        lh.hashPrevBlock = pblock->hashPrevBlock;
        lh.hashMerkleRoot = pblock->hashMerkleRoot;
        lh.nTime = pblock->nTime;
        lh.nBits = pblock->nBits;
        lh.nNonce = nNonce;
        lh.vdfSolution.fill(USHRT_MAX);

        uint256 first_hash = lh.GetSHA256();

        HCGraphUtil util{};
        std::array<uint16_t, GRAPH_SIZE> vdf_solution;
        vdf_solution.fill(USHRT_MAX);

        std::vector<uint16_t> vdf_possible;

        if (pblock->nTime <= 1726799420) {
            vdf_possible = util.findHamiltonianCycle(first_hash);
        } else if (pblock->nTime <= 1759204800) {
            vdf_possible = util.findHamiltonianCycle_V2(first_hash);
        } else {
            size_t worker_grid_size = util.workerGridSize(first_hash.ToString());
            size_t queen_bee_grid_size = util.queenBeeGridSize(worker_grid_size);

            std::vector<uint16_t> worker_graph = util.findHamiltonianCycle_V3(first_hash, worker_grid_size, 500, 1000);
            if (!worker_graph.empty()) {
                uint256 queen_bee_graph_hash = (HashWriter{} << worker_graph << first_hash).GetSHA256();
                std::vector<uint16_t> queen_bee_graph = util.findHamiltonianCycle_V3(queen_bee_graph_hash, queen_bee_grid_size, 125, 10);
                if (!queen_bee_graph.empty()) {
                    vdf_possible.insert(vdf_possible.end(), worker_graph.begin(), worker_graph.end());
                    vdf_possible.insert(vdf_possible.end(), queen_bee_graph.begin(), queen_bee_graph.end());
                }
            }
        }

        total_hashes++;

        if (!vdf_possible.empty()) {
            std::copy_n(vdf_possible.begin(), std::min(vdf_possible.size(), vdf_solution.size()), vdf_solution.begin());
            lh.vdfSolution = vdf_solution;

            uint256 gold_hash = lh.GetHash();
            if (UintToArith256(gold_hash) <= arith_uint256().SetCompact(pblock->nBits)) {
                *phash = gold_hash;
                outHeader = lh;
                return true;
            }
        }

        {
            LOCK(cs_main);
            if (pblock->hashPrevBlock != chainman.ActiveTip()->GetBlockHash()) {
                return false;
            }
        }

        if (std::chrono::steady_clock::now() - scan_start >= MINER_TEMPLATE_REFRESH) {
            return false;
        }
    }

    return false;
}

void static ShaicoinMiner(const CChainParams& chainparams,
                          const CScript& minerAddress,
                          ChainstateManager& chainman,
                          const CConnman& conman,
                          const CTxMemPool& mempool) {

    util::ThreadRename("shaicoin-miner");
    LowerMinerThreadPriority();
    try {
        // Throw an error if no script was provided.  This can happen
        // due to some internal error but also if the keypool is empty.
        // In the latter case, already the pointer is NULL.
        if (minerAddress.empty()) {
            std::cout << "mining requires a wallet" << std::endl;
            throw std::runtime_error("No coinbase script available (mining requires a wallet)");
        }

        std::cout << "ShaicoinMiner started" << std::endl;
        LogDebug(BCLog::MINING, "ShaicoinMiner thread started\n");

        int peer_wait_logs = 0;
        // This thread's own lock-free RandomX mining VM. Held across templates and
        // rebuilt only when the mining key epoch changes.
        MiningVM mining_vm;
        while (shouldMine) {
            if(make_genesis) {}
            else if (g_mine_require_peers) {
                do {
                    if (conman.GetNodeCount(ConnectionDirection::Both) > 0 && !chainman.IsInitialBlockDownload()) {
                        break;
                    }
                    if ((peer_wait_logs++ % 10) == 0) {
                        LogDebug(BCLog::MINING,
                                       "waiting for peers/IBD: peers=%d ibd=%s\n",
                                       conman.GetNodeCount(ConnectionDirection::Both),
                                       chainman.IsInitialBlockDownload() ? "yes" : "no");
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                } while (shouldMine);
            }

            //
            // Create new block
            //
            CBlockIndex* pindexPrev = nullptr;
            {
                LOCK(cs_main);
                pindexPrev = chainman.ActiveTip();
            }

            if(pindexPrev == nullptr) {
                std::cout << "ShaicoinMiner: pindexPrev was empty." << std::endl;
                break;
            }

            bool useRandomX = false;

            BlockAssembler::Options options;
            options.coinbase_output_script = minerAddress;
            options.test_block_validity = false;
            std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler{chainman.ActiveChainstate(), &mempool, options}.CreateNewBlock());
            if (!pblocktemplate.get()) {
                shouldMine = false;
                std::cout << "Error in ShaicoinMiner: Keypool ran out, please call keypoolrefill before restarting the mining thread" << std::endl;
                return;
            }

            CBlock* pblock = &pblocktemplate->block;
            const uint32_t fork_time = chainparams.GetConsensus().nRandomXV2Time;
            useRandomX = (pblock->nTime >= fork_time);

            int nextHeight = pindexPrev->nHeight + 1;

            RandomXKeyContext key_ctx;
            if (useRandomX) {
                key_ctx = LookupRandomXKeyContext(nextHeight, pindexPrev);
                if (!key_ctx.key_block_found) {
                    LogPrintLevel_(BCLog::MINING, BCLog::Level::Error, false,
                                   "RandomX key block missing: mining_height=%d key_height=%d prev_height=%d\n",
                                   nextHeight, key_ctx.key_block_height, pindexPrev->nHeight);
                    UninterruptibleSleep(std::chrono::seconds{2});
                    continue;
                }

                // Acquire (or reuse) this thread's lock-free mining VM for the
                // current key. AcquireMiningVM lazily upgrades RandomX to fast
                // (full-dataset) mode on first use — only once we are actually
                // mining post-fork blocks and past the IBD/peer gate — and rebuilds
                // only when the key epoch changes (roughly every 2048 blocks).
                if (!mining_vm.Valid() || mining_vm.Key() != key_ctx.key) {
                    mining_vm = RandomXManager::Instance().AcquireMiningVM(key_ctx.key);
                    if (!mining_vm.Valid()) {
                        LogPrintLevel_(BCLog::MINING, BCLog::Level::Error, false,
                                       "RandomX: failed to acquire mining VM at height=%d\n", nextHeight);
                        UninterruptibleSleep(std::chrono::seconds{2});
                        continue;
                    }

                    // Report huge-page status once per process. Huge pages are the
                    // single biggest RandomX mining speed knob; without them RandomX
                    // silently falls back to regular pages and runs much slower.
                    static std::atomic<bool> hp_logged{false};
                    bool hp_expected = false;
                    if (hp_logged.compare_exchange_strong(hp_expected, true)) {
                        if (RandomXManager::Instance().FastModeLargePages()) {
                            std::cout << "ShaicoinMiner: RandomX huge pages ACTIVE (optimal)." << std::endl;
                            LogPrintLevel_(BCLog::MINING, BCLog::Level::Info, false,
                                           "RandomX mining: huge pages active (optimal)\n");
                        } else {
                            std::cout << "ShaicoinMiner: WARNING - RandomX huge pages are NOT enabled; "
                                         "mining hashrate will be substantially lower. Enable huge pages "
                                         "at the OS level (Linux: sysctl -w vm.nr_hugepages=1280) for full speed."
                                      << std::endl;
                            LogPrintLevel_(BCLog::MINING, BCLog::Level::Warning, false,
                                           "RandomX mining: huge pages NOT enabled - hashrate substantially "
                                           "reduced; enable huge pages at the OS level for full speed\n");
                        }
                    }
                }

            }

            arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits);
            uint256 hash;
            
            uint32_t nNonce = []() {
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<uint32_t> dis(0, UINT32_MAX);
                return dis(gen);
            }();

            bool found = false;
            CLegacyBlockHeader legacyHeader;
            if (useRandomX) {
                found = ScanHashRandomX(pblock, nNonce, &hash, chainman, mining_vm);
            } else {
                found = ScanHashLegacy(pblock, nNonce, &hash, chainman, legacyHeader);
            }

            if (found) {
                bool needs_to_add = true;
                // Found a solution
                {
                    LOCK(cs_main);
                    if (pblock->hashPrevBlock != chainman.ActiveTip()->GetBlockHash()) {
                        needs_to_add = false;
                    }
                }

                if(needs_to_add) {
                    pblock->nNonce = nNonce;

                    uint256 legacyHash;
                    if (!useRandomX) {
                        legacyHash = legacyHeader.GetHash();
                        BlockValidationState header_state;
                        chainman.ProcessNewBlockHeaders(std::span<const CLegacyBlockHeader>{&legacyHeader, 1}, true, header_state);
                    }

                    {
                        LOCK(cs_main);
                        const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(pblock->hashPrevBlock);
                        if (pindex) {
                            chainman.UpdateUncommittedBlockStructures(*pblock, pindex);
                        }
                    }

                    bool is_new = false;
                    bool accepted = chainman.ProcessNewBlock(std::make_shared<const CBlock>(*pblock), true, true, &is_new,
                                                             useRandomX ? nullptr : &legacyHash);
                    if(accepted) {
                        LogPrintLevel_(BCLog::MINING, BCLog::Level::Info, false,
                                       "block accepted: height=%d hash=%s reward=%s\n",
                                       nextHeight, hash.GetHex(),
                                       FormatMoney(pblock->vtx[0]->vout[0].nValue));
                        std::cout << "ShaicoinMiner proof-of-work found" << std::endl;
                        std::cout << "hash: " << hash.GetHex() << std::endl;
                        std::cout << "target: " << hashTarget.GetHex() << std::endl;
                        std::cout << "generated " << FormatMoney(pblock->vtx[0]->vout[0].nValue) << std::endl;
                        std::cout << R"(
  .             *        .     .       .
       .     _     .     .            .       .
.    .   _  / |      .        .  *         _  .     .
        | \_| |                           | | __
      _ |     |                   _       | |/  |
     | \      |      ____        | |     /  |    \
     |  |     \    +/_\/_\+      | |    /   |     \
____/____\--...\___ \_||_/ ___...|__\-..|____\____/__
      .     .      |_|__|_|         .       .
   .    . .       _/ /__\ \_ .          .
      .       .    .           .         . 
                                         ___
                                      .-' \\".
                                     /`    ;--:
                                    |     (  (_)==
                                    |_ ._ '.__.;
                                    \_/`--_---_(
                                     (`--(./-\.)
                                     `|     _\ |
                                      | \  __ /
                                     /|  '.__/
                                  .'` \     |_
                                       '-__ / `-
                    )" << std::endl;
                    } else {
                        LogPrintLevel_(BCLog::MINING, BCLog::Level::Warning, false,
                                       "block rejected by ProcessNewBlock: height=%d hash=%s\n",
                                       nextHeight, hash.GetHex());
                    }
                }
            }
        }
    }
    catch (const std::runtime_error &e)
    {
        LogPrintLevel_(BCLog::MINING, BCLog::Level::Error, false, "ShaicoinMiner runtime error: %s\n", e.what());
    }
    LogDebug(BCLog::MINING, "ShaicoinMiner thread exiting\n");
    std::cout << "ShaicoinMiner Ended" << std::endl;
}

void DisplayHashRate() {
    LowerMinerThreadPriority();
    auto start_time = std::chrono::high_resolution_clock::now();
    while (shouldMine) {
        for (int i = 0; i < 50 && shouldMine; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (!shouldMine) break;

        auto current_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed_time = current_time - start_time;

        uint64_t hashes = total_hashes.exchange(0);
        double hash_rate = hashes / elapsed_time.count();

        std::cout << std::fixed << std::setprecision(3) << hash_rate << " H/s" << std::endl;
        LogDebug(BCLog::MINING, "hashrate: %.3f H/s (%llu hashes in window)\n", hash_rate, hashes);

        start_time = std::chrono::high_resolution_clock::now();
    }
}

void GenerateShaicoins(std::optional<CScript> minerAddress,
                       const CChainParams& chainparams,
                       ChainstateManager& chainman,
                       const CConnman& conman,
                       const CTxMemPool& mempool,
                       size_t nThreads)
{
    static std::vector<std::thread> minerThreads;

    shouldMine = false;

    for (auto& thread : minerThreads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    minerThreads.clear();

    if(minerAddress.has_value() == false) {
        return;
    }

    // Default (nThreads == 0, i.e. no -minethreads specified): use ALL logical
    // cores. Pass -minethreads=N to cap it.
    const bool threads_defaulted = (nThreads == 0);
    if (nThreads == 0) {
        nThreads = GetNumCores();   // std::thread::hardware_concurrency()
    }
    if (nThreads < 1) {
        nThreads = 1;
    }

    g_mine_require_peers = gArgs.GetBoolArg("-minerequirepeers", true);

    std::cout << "ShaicoinMiner: using " << nThreads << " mining thread(s)"
              << (threads_defaulted ? " (all logical cores; override with -minethreads=N)" : " (from -minethreads)")
              << std::endl;

    LogPrintLevel_(BCLog::MINING, BCLog::Level::Info, false,
                   "GenerateShaicoins: threads=%u (%s) minerequirepeers=%s fork_time=%u key_interval=%d key_delay=%d\n",
                   nThreads, threads_defaulted ? "default=all-cores" : "user-specified",
                   g_mine_require_peers ? "yes" : "no",
                   chainparams.GetConsensus().nRandomXV2Time,
                   Consensus::RANDOMX_KEY_INTERVAL,
                   Consensus::RANDOMX_KEY_DELAY);

    shouldMine = true;

    minerThreads.reserve(nThreads + 1);
    for (size_t i = 0; i < nThreads; i++) {
        minerThreads.emplace_back(ShaicoinMiner,
                                  std::cref(chainparams),
                                  std::cref(*minerAddress),
                                  std::ref(chainman),
                                  std::cref(conman),
                                  std::cref(mempool));
    }
    minerThreads.emplace_back(DisplayHashRate);
}
