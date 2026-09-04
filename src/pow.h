// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include <consensus/params.h>

#include <array>
#include <stdint.h>

static const size_t GRAPH_SIZE = 2008;

class CBlockHeader;
class CBlockIndex;
class uint256;
class arith_uint256;

/**
 * Convert nBits value to target.
 *
 * @param[in] nBits     compact representation of the target
 * @param[in] pow_limit PoW limit (consensus parameter)
 *
 * @return              the proof-of-work target or nullopt if the nBits value
 *                      is invalid (due to overflow or exceeding pow_limit)
 */
std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit);

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&);

/**
 * Post-fork RandomX headers must strictly advance time relative to their
 * parent. Legacy VDF headers retain their historical timestamp rules.
 */
bool IsPostForkTimestampMonotonic(const CBlockHeader& block,
                                  const CBlockIndex& pindexPrev,
                                  const Consensus::Params& params);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(int nTime,
                      uint256 first_sha_hash,
                      uint256 block_sha_hash,
                      unsigned int nBits,
                      const std::array<uint16_t, GRAPH_SIZE>& vdfSolution,
                      const Consensus::Params& params);

/** Fast PoW check - only validates target difficulty without VDF verification (for IBD sampling) */
bool CheckProofOfWorkFast(uint256 block_sha_hash,
                          unsigned int nBits,
                          const Consensus::Params& params);

enum class RandomXPoWError {
    OK,
    BAD_TARGET,
    MISSING_KEY_BLOCK,
    HIGH_HASH,
    // The RandomX hash could not be genuinely computed (e.g. the node failed to
    // allocate/initialize the RandomX cache or VM). This MUST be treated as a
    // verification failure (fail-closed): a failed computation yields a null
    // hash that would otherwise satisfy any target.
    COMPUTE_FAILED,
};

RandomXPoWError CheckProofOfWorkRandomXDetailed(const CBlockHeader& header,
                                                int height,
                                                const CBlockIndex* pindexPrev,
                                                const Consensus::Params& params,
                                                uint256* powHashOut = nullptr,
                                                arith_uint256* targetOut = nullptr,
                                                uint256* preimageOut = nullptr,
                                                int* keyHeightOut = nullptr,
                                                uint256* keyBlockHashOut = nullptr);

bool CheckProofOfWorkRandomX(const CBlockHeader& header,
                             int height,
                             const CBlockIndex* pindexPrev,
                             const Consensus::Params& params,
                             uint256* powHashOut = nullptr);

/**
 * Verify a RandomX header proof-of-work using an explicitly supplied RandomX
 * key (derived by the caller from the relevant key block). Used by the headers
 * sync (presync/redownload) path, which does not have block index context for
 * the headers it is validating.
 */
bool CheckProofOfWorkRandomXWithKey(const CBlockHeader& header,
                                    const std::array<uint8_t, Consensus::RANDOMX_KEY_MAX_BYTES>& key,
                                    const Consensus::Params& params,
                                    uint256* powHashOut = nullptr);

uint256 RandomXPreimageHash(const CBlockHeader& header);

/**
 * Return false if the proof-of-work requirement specified by new_nbits at a
 * given height is not possible, given the proof-of-work on the prior block as
 * specified by old_nbits.
 *
 * This function only checks that the new value is within a factor of 4 of the
 * old value for blocks at the difficulty adjustment interval, and otherwise
 * requires the values to be the same.
 *
 * Always returns true on networks where min difficulty blocks are allowed,
 * such as regtest/testnet.
 */
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits, int64_t block_time);

#endif // BITCOIN_POW_H
