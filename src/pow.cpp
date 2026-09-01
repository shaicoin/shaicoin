// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
#include <miner.h>
#include <hash.h>
#include <util/check.h>
#include <randomx_manager.h>

typedef long long int64;

static const int64 nTargetSpacing = 2 * 60;  // 2 minute block time target
static arith_uint256 bnProofOfWorkLimit(~arith_uint256(0) >> 9);
// RandomX is cheaper to mine than the legacy ShaiHive algorithm, so its
// easiest-allowed target (lowest difficulty) is raised 25x relative to the
// base proof-of-work limit.
static const arith_uint256 bnRandomXProofOfWorkLimit(bnProofOfWorkLimit / 25);
static_assert(nTargetSpacing != 0);

int64_t static mapNumber(int64_t x, int64_t in_min, int64_t in_max, int64_t out_min, int64_t out_max) {
  return (x - in_min) * (out_max - out_min) / (in_max - in_min) + out_min;
}

unsigned int GetNextWorkRequired_ShaiHive_V1(const CBlockIndex* pindexLast,
                                          const CBlockHeader *pblock,
                                          const Consensus::Params& params) {    
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);

    uint64_t difference = pblock->GetBlockTime() - pindexLast->GetBlockTime();
    int64_t balanced_diff = difference - nTargetSpacing;

    if(balanced_diff >= 42) {
        // need to make it easier
        if(balanced_diff > 600) {
            balanced_diff = 600;
        }
        bnNew *= mapNumber(balanced_diff, 42, 600, 102, 111);
        bnNew /= 100;
    } else if(balanced_diff <= -42) {
        // need to make it harder
        if(balanced_diff < -nTargetSpacing) {
            balanced_diff = -nTargetSpacing;
        }
        bnNew *= 100;
        bnNew /= mapNumber(-balanced_diff, 42, nTargetSpacing, 101, 105);
    }

    if (bnNew > bnProofOfWorkLimit) {
        bnNew = bnProofOfWorkLimit;
    }

    return bnNew.GetCompact();
}

unsigned int GetNextWorkRequired_ShaiHive_V2(const CBlockIndex* pindexLast,
                                          const CBlockHeader *pblock,
                                          const Consensus::Params& params) {    
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);

    uint64_t difference = pindexLast->GetBlockTime() - pindexLast->GetAncestor(pindexLast->nHeight - 1)->GetBlockTime();
    int64_t balanced_diff = difference - nTargetSpacing;

    if(balanced_diff >= 42) {
        // need to make it easier
        if(balanced_diff > 600) {
            balanced_diff = 600;
        }
        bnNew *= mapNumber(balanced_diff, 42, 600, 102, 111);
        bnNew /= 100;
    } else if(balanced_diff <= -42) {
        // need to make it harder
        if(balanced_diff < -nTargetSpacing) {
            balanced_diff = -nTargetSpacing;
        }
        bnNew *= 100;
        bnNew /= mapNumber(-balanced_diff, 42, nTargetSpacing, 101, 105);
    }

    if (bnNew > bnProofOfWorkLimit) {
        bnNew = bnProofOfWorkLimit;
    }

    return bnNew.GetCompact();
}

unsigned int GetNextWorkRequired_ShaiHive_DiffRebound(const CBlockIndex* pindexLast,
                                                      const CBlockHeader *pblock,
                                                      const Consensus::Params& params) {  
    uint64_t bail_out_difference = pblock->GetBlockTime() - pindexLast->GetBlockTime();
    
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);

    const int five_minutes = 300;
    if (bail_out_difference > five_minutes) {
        uint64_t num_5min_intervals = bail_out_difference / five_minutes;
        for (uint64_t i = 0; i < num_5min_intervals; i++) {
            bnNew *= 200;
            bnNew /= 100;
            if (bnNew > bnProofOfWorkLimit) {
                break;
            }
        }
    }

    uint64_t difference = pindexLast->GetBlockTime() - pindexLast->GetAncestor(pindexLast->nHeight - 1)->GetBlockTime();
    int64_t balanced_diff = difference - nTargetSpacing;

    if(balanced_diff >= 42) {
        if(balanced_diff > 600) {
            balanced_diff = 600;
        }
        bnNew *= mapNumber(balanced_diff, 42, 600, 102, 111);
        bnNew /= 100;
    } else if(balanced_diff <= -42) {
        if(balanced_diff < -nTargetSpacing) {
            balanced_diff = -nTargetSpacing;
        }
        bnNew *= 100;
        bnNew /= mapNumber(-balanced_diff, 42, nTargetSpacing, 101, 105);
    }

    if (bnNew > bnProofOfWorkLimit) {
        bnNew = bnProofOfWorkLimit;
    }

    return bnNew.GetCompact();
}

unsigned int GetNextWorkRequired_ShaiHive_DiffRebound_V2(const CBlockIndex* pindexLast,
                                                         const CBlockHeader *pblock,
                                                         const Consensus::Params& params,
                                                         int64_t forkTimestamp) {
    if (pindexLast->GetBlockTime() < forkTimestamp) {
        return bnProofOfWorkLimit.GetCompact();
    }
    return GetNextWorkRequired_ShaiHive_V2(pindexLast, pblock, params);
}

unsigned int GetNextWorkRequired_RandomX(const CBlockIndex* pindexLast,
                                         const CBlockHeader *pblock,
                                         const Consensus::Params& params) {
    // Regtest is explicitly configured with fPowNoRetargeting.  Let it use
    // its own powLimit so a post-fork RandomX block can be mined interactively
    // during local consensus tests. Mainnet and testnet retain the tighter
    // RandomX-specific limit below.
    if (params.fPowNoRetargeting) {
        return UintToArith256(params.powLimit).GetCompact();
    }
    if (!pindexLast->IsPostFork()) {
        arith_uint256 bnSeed = bnRandomXProofOfWorkLimit;
        bnSeed /= 10;
        return bnSeed.GetCompact();
    }
    arith_uint256 bnNew;
    bnNew.SetCompact(GetNextWorkRequired_ShaiHive_DiffRebound(pindexLast, pblock, params));
    if (bnNew > bnRandomXProofOfWorkLimit) {
        bnNew = bnRandomXProofOfWorkLimit;
    }
    return bnNew.GetCompact();
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast,
                                 const CBlockHeader *pblock,
                                 const Consensus::Params& params) {
    assert(pindexLast != nullptr);
    if (pblock->GetBlockTime() >= params.nRandomXV2Time) {
        return GetNextWorkRequired_RandomX(pindexLast, pblock, params);
    }
    if(pindexLast->nHeight <= 4349) {
        return GetNextWorkRequired_ShaiHive_V1(pindexLast, pblock, params);
    } else if(pblock->GetBlockTime() <= 1759204800) {
        return GetNextWorkRequired_ShaiHive_V2(pindexLast, pblock, params);
    } else if(pblock->GetBlockTime() <= 1759204800 + 86400) {
        return GetNextWorkRequired_ShaiHive_DiffRebound(pindexLast, pblock, params);
    } else if(pblock->GetBlockTime() <= 1766797200) {
        return GetNextWorkRequired_ShaiHive_V2(pindexLast, pblock, params);
    } else if(pblock->GetBlockTime() <= 1766797200 + 86400) {
        return GetNextWorkRequired_ShaiHive_DiffRebound_V2(pindexLast, pblock, params, 1766797200);
    }
    return GetNextWorkRequired_ShaiHive_V2(pindexLast, pblock, params);
}

bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits, int64_t block_time)
{
    arith_uint256 old_target, new_target;
    old_target.SetCompact(old_nbits);
    new_target.SetCompact(new_nbits);

    if (new_target == 0 || new_target > bnProofOfWorkLimit) {
        return false;
    }

    if (block_time >= 1759204800 && block_time <= 1766797200 + 86400) {
        return true;
    }

    if (block_time >= params.nRandomXV2Time) {
        return true;
    }

    arith_uint256 max_increase = old_target;
    arith_uint256 max_decrease = old_target;

    max_increase *= 112;
    max_increase /= 100;

    max_decrease *= 100;
    max_decrease /= 106;

    if (new_target > max_increase || new_target < max_decrease) {
        return false;
    }
    return true;
}

std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(pow_limit))
        return {};

    return bnTarget;
}

bool CheckProofOfWork_V1(uint256 first_sha_hash,
                         unsigned int nBits,
                         const std::array<uint16_t, GRAPH_SIZE>& vdfSolution,
                         const Consensus::Params& params) {
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit)) {
        return false;
    }

    uint256 gold_hash = (HashWriter{} << vdfSolution).GetSHA256();
    // Check proof of work matches claimed amount
    if (UintToArith256(gold_hash) > bnTarget) {
        return false;
    }

    // construct second sha hash
    uint256 second_hash = (HashWriter{} << first_sha_hash).GetSHA256();
    
    // construct VDF Graph
    uint256 graph_construction_hash = first_sha_hash ^ second_hash;
    HCGraphUtil util{};
    size_t grid_size = util.getGridSize(graph_construction_hash.ToString());
    std::vector<std::vector<bool>> graph = util.generateGraph(graph_construction_hash, grid_size);

    // verify the vdf solution
    return util.verifyHamiltonianCycle(graph, vdfSolution);
}


bool CheckProofOfWork_V2(uint256 first_sha_hash,
                         uint256 block_sha_hash,
                         unsigned int nBits,
                         const std::array<uint16_t, GRAPH_SIZE>& vdfSolution,
                         const Consensus::Params& params) {
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit)) {
        return false;
    }

    if (UintToArith256(block_sha_hash) > bnTarget) {
        return false;
    }

    // construct VDF Graph
    HCGraphUtil util{};
    size_t grid_size = util.getGridSize(first_sha_hash.ToString());
    std::vector<std::vector<bool>> graph = util.generateGraph(first_sha_hash, grid_size);
    // verify the vdf solution
    return util.verifyHamiltonianCycle(graph, vdfSolution);
}

bool CheckProofOfWork_V3(uint256 first_sha_hash,
                         uint256 block_sha_hash,
                         unsigned int nBits,
                         const std::array<uint16_t, GRAPH_SIZE>& vdfSolution,
                         const Consensus::Params& params) {
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit)) {
        return false;
    }

    if (UintToArith256(block_sha_hash) > bnTarget) {
        return false;
    }

    // construct VDF Graph
    HCGraphUtil util{};
    size_t grid_size = util.getGridSize_V2(first_sha_hash.ToString());
    std::vector<std::vector<bool>> graph = util.generateGraph_V2(first_sha_hash, grid_size);
    // verify the vdf solution
    return util.verifyHamiltonianCycle(graph, vdfSolution);
}

bool CheckProofOfWork_V4(uint256 first_sha_hash,
                         uint256 block_sha_hash,
                         unsigned int nBits,
                         const std::array<uint16_t, GRAPH_SIZE>& vdfSolution,
                         const Consensus::Params& params) {
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit)) {
        return false;
    }

    if (UintToArith256(block_sha_hash) > bnTarget) {
        return false;
    }

    // construct VDF Graph
    HCGraphUtil util{};
    size_t grid_size = util.getGridSize_V2(first_sha_hash.ToString());
    std::vector<std::vector<bool>> graph = util.generateGraph_V2(first_sha_hash, grid_size);
    // verify the vdf solution
    return util.verifyHamiltonianCycle_V2(graph, vdfSolution);
}

bool CheckProofOfWork_V5_V6(uint256 first_sha_hash,
                            uint256 block_sha_hash,
                            unsigned int nBits,
                            const std::array<uint16_t, GRAPH_SIZE>& vdfSolution,
                            const Consensus::Params& params,
                            bool useCanonicalPath) {
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit)) {
        return false;
    }

    if (UintToArith256(block_sha_hash) > bnTarget) {
        return false;
    }

    // construct VDF Graph
    HCGraphUtil util{};
    size_t worker_grid_size = util.workerGridSize(first_sha_hash.ToString());
    size_t queen_bee_grid_size = util.queenBeeGridSize(worker_grid_size);

    std::vector<uint16_t> worker_solution(worker_grid_size);
    std::copy_n(vdfSolution.begin(), worker_grid_size, worker_solution.begin());

    // Extract queen bee solution (remaining elements after worker_grid_size)
    std::vector<uint16_t> queen_bee_solution(queen_bee_grid_size);
    std::copy_n(vdfSolution.begin() + worker_grid_size,
                vdfSolution.size() - worker_grid_size, 
                queen_bee_solution.begin());
    
    // generate the worker graph at 50%
    std::vector<std::vector<bool>> worker_graph = util.generateGraph_V3(first_sha_hash, worker_grid_size, 500);

    // Verify worker solution
    bool worker_valid = useCanonicalPath 
        ? util.verifyHamiltonianCycle_V4(worker_graph, worker_solution)
        : util.verifyHamiltonianCycle_V3(worker_graph, worker_solution);
    if (!worker_valid){
        return false;
    }

    // Generate hash for queen bee graph using worker solution
    uint256 queen_bee_graph_hash = (HashWriter{} << worker_solution << first_sha_hash).GetSHA256();

    // Generate queen bee graph at 12.5%
    std::vector<std::vector<bool>> queen_bee_graph = util.generateGraph_V3(queen_bee_graph_hash, queen_bee_grid_size, 125);
    
    // Verify queen bee solution
    return useCanonicalPath
        ? util.verifyHamiltonianCycle_V4(queen_bee_graph, queen_bee_solution)
        : util.verifyHamiltonianCycle_V3(queen_bee_graph, queen_bee_solution);
}


bool CheckProofOfWork(int nTime,
                      uint256 first_sha_hash,
                      uint256 block_sha_hash,
                      unsigned int nBits,
                      const std::array<uint16_t, GRAPH_SIZE>& vdfSolution,
                      const Consensus::Params& params) {
    if(nTime <= 1723869065) {
        return CheckProofOfWork_V1(first_sha_hash, nBits, vdfSolution, params);
    } else if(nTime <= 1726799420) {
        return CheckProofOfWork_V2(first_sha_hash, block_sha_hash, nBits, vdfSolution, params);
    } else if(nTime <= 1731341471) {
        return CheckProofOfWork_V3(first_sha_hash, block_sha_hash, nBits, vdfSolution, params);
    } else if(nTime <= 1759204800) {
        return CheckProofOfWork_V4(first_sha_hash, block_sha_hash, nBits, vdfSolution, params);
    }
    return CheckProofOfWork_V5_V6(
        first_sha_hash, 
        block_sha_hash, 
        nBits, 
        vdfSolution, 
        params, 
        nTime > 1766797200);
}

bool CheckProofOfWorkFast(uint256 block_sha_hash,
                          unsigned int nBits,
                          const Consensus::Params& params) {
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit)) {
        return false;
    }

    if (UintToArith256(block_sha_hash) > bnTarget) {
        return false;
    }

    return true;
}

static bool RandomXTargetFromHeader(const CBlockHeader& header,
                                    const Consensus::Params& params,
                                    arith_uint256& bnTarget)
{
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(header.nBits, &fNegative, &fOverflow);

    const arith_uint256 randomx_limit = params.fPowNoRetargeting
        ? UintToArith256(params.powLimit)
        : bnRandomXProofOfWorkLimit;
    if (fNegative || bnTarget == 0 || fOverflow ||
        bnTarget > UintToArith256(params.powLimit) ||
        bnTarget > randomx_limit) {
        return false;
    }
    return true;
}

uint256 RandomXPreimageHash(const CBlockHeader& header)
{
    return (HashWriter{} << header).GetHash();
}

RandomXPoWError CheckProofOfWorkRandomXDetailed(const CBlockHeader& header,
                                                int height,
                                                const CBlockIndex* pindexPrev,
                                                const Consensus::Params& params,
                                                uint256* powHashOut,
                                                arith_uint256* targetOut,
                                                uint256* preimageOut,
                                                int* keyHeightOut,
                                                uint256* keyBlockHashOut)
{
    arith_uint256 bnTarget;
    if (!RandomXTargetFromHeader(header, params, bnTarget)) {
        return RandomXPoWError::BAD_TARGET;
    }
    if (targetOut) *targetOut = bnTarget;

    const RandomXKeyContext key_ctx = LookupRandomXKeyContext(height, pindexPrev);
    if (!key_ctx.key_block_found) {
        if (keyHeightOut) *keyHeightOut = key_ctx.key_block_height;
        return RandomXPoWError::MISSING_KEY_BLOCK;
    }
    if (keyHeightOut) *keyHeightOut = key_ctx.key_block_height;
    if (keyBlockHashOut) *keyBlockHashOut = key_ctx.key_block_hash;

    uint256 H = RandomXPreimageHash(header);
    if (preimageOut) *preimageOut = H;
    uint256 R = ComputeRandomXHash(key_ctx.key, H.data(), H.size());

    if (powHashOut) {
        *powHashOut = R;
    }

    // Fail closed. The RandomX layer returns a null (all-zero) hash whenever it
    // cannot allocate/initialize its cache or VM (see RandomXManager::HashWithKey).
    // Zero satisfies every valid target (0 <= target), so accepting it would let
    // a node that failed to bring up RandomX admit blocks with NO proof of work
    // at all. A genuine RandomX output of exactly zero has probability 2^-256, so
    // rejecting a null result here is consensus-safe and closes the fail-open.
    if (R.IsNull()) {
        return RandomXPoWError::COMPUTE_FAILED;
    }

    if (UintToArith256(R) > bnTarget) {
        return RandomXPoWError::HIGH_HASH;
    }

    return RandomXPoWError::OK;
}

bool CheckProofOfWorkRandomX(const CBlockHeader& header,
                             int height,
                             const CBlockIndex* pindexPrev,
                             const Consensus::Params& params,
                             uint256* powHashOut)
{
    return CheckProofOfWorkRandomXDetailed(header, height, pindexPrev, params, powHashOut, nullptr, nullptr, nullptr, nullptr) == RandomXPoWError::OK;
}

bool CheckProofOfWorkRandomXWithKey(const CBlockHeader& header,
                                    const std::array<uint8_t, Consensus::RANDOMX_KEY_MAX_BYTES>& key,
                                    const Consensus::Params& params,
                                    uint256* powHashOut)
{
    arith_uint256 bnTarget;
    if (!RandomXTargetFromHeader(header, params, bnTarget)) {
        return false;
    }

    uint256 H = RandomXPreimageHash(header);
    uint256 R = ComputeRandomXHash(key, H.data(), H.size());

    if (powHashOut) {
        *powHashOut = R;
    }

    // Fail closed on a null (all-zero) hash: it means the RandomX layer could
    // not compute (alloc/init failure) and zero would otherwise satisfy every
    // target. See CheckProofOfWorkRandomXDetailed for the full rationale.
    if (R.IsNull()) {
        return false;
    }

    if (UintToArith256(R) > bnTarget) {
        return false;
    }

    return true;
}
