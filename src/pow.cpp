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

typedef long long int64;

static const int64 nTargetSpacing = 2 * 60;  // 2 minute block time target
static arith_uint256 bnProofOfWorkLimit(~arith_uint256(0) >> 9);
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

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast,
                                 const CBlockHeader *pblock,
                                 const Consensus::Params& params) {
    assert(pindexLast != nullptr);
    if(pindexLast->nHeight <= 4349) {
        return GetNextWorkRequired_ShaiHive_V1(pindexLast, pblock, params);
    }
    return GetNextWorkRequired_ShaiHive_V2(pindexLast, pblock, params);
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    arith_uint256 old_target, new_target;
    old_target.SetCompact(old_nbits);
    new_target.SetCompact(new_nbits);

    // Calculate the permitted range
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
    }
    return CheckProofOfWork_V3(first_sha_hash, block_sha_hash, nBits, vdfSolution, params);
}