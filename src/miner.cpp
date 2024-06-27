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
#include "timedata.h"
#include "txmempool.h"
#include <util/moneystr.h>
#include "validationinterface.h"

#include <logging.h>
#include <common/system.h>
#include <util/threadnames.h>
#include <util/thread.h>
#include <validation.h>
#include <util/signalinterrupt.h>

#include <boost/thread.hpp>
#include <queue>

#include <randomx.h>
#include <random>

using namespace std;
using node::BlockAssembler;
using node::CBlockTemplate;
using node::UpdateTime;

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

bool static ScanHash(CBlockHeader *pblock, uint32_t& nNonce, uint256 *phash, ChainstateManager& chainman) {
    int64_t nStart = GetTime();
    while (shouldMine) {
        nNonce++;
        pblock->nNonce = nNonce;
        //
        //  Need to do the following POW
        //  - Needs to sha256 once
        uint256 first_hash = pblock->GetSHA256();
        //  - Needs to sha256 twice
        uint256 second_hash = (HashWriter{} << first_hash).GetSHA256();
        //  - utilizing the first and second sha256 create randomx hash
        uint256 randomx_hash = calculate_randomx_hash(first_hash.ToString(),
                                                      second_hash.ToString());
        //  - utilizing the second sha256 and randomx hash. XOR and construct the graph.
        uint256 graph_construction_hash = second_hash ^ randomx_hash;
        //  - Find a hamiltonian cycle
        HCGraphUtil util{};
        std::array<uint16_t, 1992> vdf_solution;
        vdf_solution.fill(USHRT_MAX);

        std::vector<uint16_t> vdf_possible = util.findHamiltonianCycle(graph_construction_hash);

        // Check for empty
        if(vdf_possible.empty()) {
            continue;
        }

        std::copy_n(vdf_possible.begin(), std::min(vdf_possible.size(), vdf_solution.size()), vdf_solution.begin());

        for (size_t attempts = 0; attempts < 1992; ++attempts) {
            uint256 gold_hash = (HashWriter{} << vdf_solution).GetSHA256();
            //std::cout << "Gold hash: " << gold_hash.ToString() << std::endl;
            if (UintToArith256(gold_hash) <= arith_uint256().SetCompact(pblock->nBits)) {
                pblock->hashRandomX = randomx_hash;
                pblock->vdfSolution = vdf_solution;

                *phash = pblock->GetHash();

                return true;
            } else {
                util.shift(vdf_solution);
            }
        }

        bool stale_block = false;
        {
            LOCK(cs_main);
            if (pblock->hashPrevBlock != chainman.ActiveTip()->GetBlockHash()) {
                stale_block = true;
            }
        }

        if(stale_block || (GetTime() - nStart > 60)) {
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
    try {
        // Throw an error if no script was provided.  This can happen
        // due to some internal error but also if the keypool is empty.
        // In the latter case, already the pointer is NULL.
        if (minerAddress.empty()) {
            std::cout << "mining requires a wallet" << std::endl;
            throw std::runtime_error("No coinbase script available (mining requires a wallet)");
        }

        std::cout << "ShaicoinMiner started" << std::endl;

        while (shouldMine) {
            // Busy-wait for the network to come online so we don't waste time mining
            // on an obsolete chain.
            do {
                if (conman.GetNodeCount(ConnectionDirection::Both) > 0 && !chainman.IsInitialBlockDownload()) {
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                std::cout << "ShaicoinMiner Waiting for peers" << std::endl;
            } while (shouldMine);

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

            std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler{chainman.ActiveChainstate(), &mempool}.CreateNewBlock(minerAddress));
            if (!pblocktemplate.get()) {
                shouldMine = false;
                std::cout << "Error in ShaicoinMiner: Keypool ran out, please call keypoolrefill before restarting the mining thread" << std::endl;
                return;
            }

            CBlock* pblock = &pblocktemplate->block;
            pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);

            //
            // Search
            //
            arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits);
            uint256 hash;
            
            //uint32_t nNonce = 0;
            uint32_t nNonce = []() {
                std::random_device rd;  // Initialize a random device
                std::mt19937 gen(rd()); // Seed the Mersenne Twister generator
                std::uniform_int_distribution<uint32_t> dis(0, UINT32_MAX); // Define the distribution range
                return dis(gen); // Generate and return the random number
            }();

            // Check if something found
            if (ScanHash(pblock, nNonce, &hash, chainman)) {
                bool needs_to_add = true;
                // Found a solution
                {
                    LOCK(cs_main);
                    if (pblock->hashPrevBlock != chainman.ActiveTip()->GetBlockHash()) {
                        needs_to_add = false;
                    }
                }

                if(needs_to_add) {
                    {
                        LOCK(cs_main);
                        const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(pblock->hashPrevBlock);
                        if (pindex) {
                            chainman.UpdateUncommittedBlockStructures(*pblock, pindex);
                        }
                    }

                    bool is_new = false;
                    bool accepted = chainman.ProcessNewBlock(std::make_shared<const CBlock>(*pblock), true, true, &is_new);
                    if(accepted) {
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
                    }
                }
            }
        }
    }
    catch (const std::runtime_error &e)
    {
        LogPrintf("ShaicoinMiner runtime error: %s\n", e.what());
    }
    std::cout << "ShaicoinMiner Ended" << std::endl;
}

void GenerateShaicoins(std::optional<CScript> minerAddress,
                       const CChainParams& chainparams,
                       ChainstateManager& chainman,
                       const CConnman& conman,
                       const CTxMemPool& mempool)
{
    static std::vector<std::thread> minerThreads;

    bool use_all_cores = true;

    size_t nThreads = use_all_cores ? GetNumCores() : 1;

    shouldMine = false;

    // Stop and join all threads before starting new ones
    for (auto& thread : minerThreads) {
        if (thread.joinable())
            thread.join();
    }
    minerThreads.clear();

    if(minerAddress.has_value() == false) {
        return;
    }

    shouldMine = true;

    minerThreads.resize(nThreads);
    for (size_t i = 0; i < nThreads; i++) {
        minerThreads[i] = std::thread(ShaicoinMiner,
                                      std::cref(chainparams),
                                      std::cref(*minerAddress),
                                      std::ref(chainman),
                                      std::cref(conman),
                                      std::cref(mempool));
    }
}