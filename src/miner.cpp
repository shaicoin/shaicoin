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
#include <random>

using namespace std;
using node::BlockAssembler;
using node::CBlockTemplate;
using node::UpdateTime;

bool make_genesis = false; // remove this and any code it touches
// also change where pblock is set

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
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
    genesis.vdfSolution.fill(USHRT_MAX);

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
        //  - utilizing the first_hash and second sha256 hash. XOR and construct the graph.
        uint256 graph_construction_hash = first_hash ^ second_hash;
        //  - Find a hamiltonian cycle
        HCGraphUtil util{};
        std::array<uint16_t, GRAPH_SIZE> vdf_solution;
        vdf_solution.fill(USHRT_MAX);

        std::vector<uint16_t> vdf_possible = util.findHamiltonianCycle(graph_construction_hash);

        // Check for empty
        if(vdf_possible.empty()) {
            continue;
        }

        std::copy_n(vdf_possible.begin(), std::min(vdf_possible.size(), vdf_solution.size()), vdf_solution.begin());

        uint256 gold_hash = (HashWriter{} << vdf_solution).GetSHA256();
        
        total_hashes++;

        if (UintToArith256(gold_hash) <= arith_uint256().SetCompact(pblock->nBits)) {
            pblock->vdfSolution = vdf_solution;

            *phash = pblock->GetHash();

            if(make_genesis) {
                std::cout << "Found gold: " << nNonce << std::endl;
                for(auto item : vdf_solution) {
                    std::cout << item << ", ";
                }
                std::cout << std::endl;
                shouldMine = false;
                return false;
            }

            return true;
        }

        bool stale_block = false;
        {
            LOCK(cs_main);
            if (pblock->hashPrevBlock != chainman.ActiveTip()->GetBlockHash()) {
                stale_block = true;
            }
        }

        if(stale_block || (GetTime() - nStart > 15)) {
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
            if(make_genesis) {}
            else {
                do {
                    if (conman.GetNodeCount(ConnectionDirection::Both) > 0 && !chainman.IsInitialBlockDownload()) {
                        break;
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

            std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler{chainman.ActiveChainstate(), &mempool}.CreateNewBlock(minerAddress));
            if (!pblocktemplate.get()) {
                shouldMine = false;
                std::cout << "Error in ShaicoinMiner: Keypool ran out, please call keypoolrefill before restarting the mining thread" << std::endl;
                return;
            }

            //auto genesis = CreateGenesisBlock(1723206420, 42, 0x1f7fffff, 1, 11 * COIN);
            //CBlock* pblock = &genesis;
            CBlock* pblock = &pblocktemplate->block;
            pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);

            //
            // Search
            //
            arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits);
            uint256 hash;
            
            uint32_t nNonce = []() {
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<uint32_t> dis(0, UINT32_MAX);
                return dis(gen);
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

void DisplayHashRate() {
    auto start_time = std::chrono::high_resolution_clock::now();
    while (shouldMine) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        auto current_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed_time = current_time - start_time;

        uint64_t hashes = total_hashes.exchange(0);
        double hash_rate = hashes / elapsed_time.count();

        std::cout << std::fixed << std::setprecision(3) << hash_rate << " H/s" << std::endl;

        start_time = std::chrono::high_resolution_clock::now();
    }
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

    minerThreads.resize(nThreads + 1);
    for (size_t i = 0; i < nThreads; i++) {
        minerThreads[i] = std::thread(ShaicoinMiner,
                                      std::cref(chainparams),
                                      std::cref(*minerAddress),
                                      std::ref(chainman),
                                      std::cref(conman),
                                      std::cref(mempool));
    }

    minerThreads.emplace_back(DisplayHashRate);
}