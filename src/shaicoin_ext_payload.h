// Copyright (c) 2024 The Shaicoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SHAICOIN_EXT_PAYLOAD_H
#define SHAICOIN_EXT_PAYLOAD_H

#include <serialize.h>
#include <streams.h>
#include <consensus/merkle.h>
#include <uint256.h>
#include <hash.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <algorithm>
#include <utility>
#include <vector>
#include <optional>

static constexpr uint8_t SHAI_EXT_COMMITMENT_PREFIX[] = {'S', 'H', 'A', 'I'};
static constexpr size_t SHAI_EXT_COMMITMENT_PREFIX_LEN = 4;

struct ShaicoinExtPayload {
    uint16_t ext_version{0};
    uint16_t flags{0};
    uint256 path_seed;
    std::vector<uint8_t> path_proof;
    std::vector<uint8_t> reserved;

    SERIALIZE_METHODS(ShaicoinExtPayload, obj)
    {
        READWRITE(obj.ext_version, obj.flags, obj.path_seed, obj.path_proof, obj.reserved);
    }

    uint256 GetCommitmentHash() const
    {
        DataStream ss{};
        ss << *this;
        return (HashWriter{} << Span<const uint8_t>{(const uint8_t*)ss.data(), ss.size()}).GetSHA256();
    }
};

inline uint256 ComputePathSeed(const uint256& prevBlockHash, const uint256& keyBlockHash,
                                const uint256& merkleRoot, uint32_t nTime)
{
    HashWriter hw{};
    hw << prevBlockHash << keyBlockHash << merkleRoot << nTime;
    return hw.GetSHA256();
}

inline std::vector<uint8_t> BuildExtCommitmentScript(const uint256& ext_commitment32)
{
    std::vector<uint8_t> script;
    script.push_back(OP_RETURN);
    script.push_back(SHAI_EXT_COMMITMENT_PREFIX_LEN + 32);
    script.insert(script.end(), std::begin(SHAI_EXT_COMMITMENT_PREFIX), std::end(SHAI_EXT_COMMITMENT_PREFIX));
    script.insert(script.end(), ext_commitment32.begin(), ext_commitment32.end());
    return script;
}

inline bool IsShaicoinExtCommitmentScript(const CScript& scriptPubKey)
{
    if (scriptPubKey.size() != 2 + SHAI_EXT_COMMITMENT_PREFIX_LEN + 32 ||
        scriptPubKey[0] != OP_RETURN ||
        scriptPubKey[1] != SHAI_EXT_COMMITMENT_PREFIX_LEN + 32) {
        return false;
    }

    return std::equal(std::begin(SHAI_EXT_COMMITMENT_PREFIX),
                      std::end(SHAI_EXT_COMMITMENT_PREFIX),
                      scriptPubKey.begin() + 2);
}

// Bind the post-fork coinbase body to the extended header. Keeping this in one
// helper prevents the local miner and external-template RPC from producing
// subtly different commitments for the same candidate block.
inline bool ApplyShaicoinExtCommitment(CBlock& block, const uint256& keyBlockHash)
{
    if (block.vtx.empty()) {
        return false;
    }

    ShaicoinExtPayload extPayload;
    extPayload.ext_version = 1;
    extPayload.flags = 0;
    extPayload.path_seed = ComputePathSeed(block.hashPrevBlock, keyBlockHash, uint256{}, block.nTime);

    const uint256 commitment = extPayload.GetCommitmentHash();
    CMutableTransaction coinbaseTx(*block.vtx[0]);
    CTxOut commitOut;
    commitOut.nValue = 0;
    const auto commitScript = BuildExtCommitmentScript(commitment);
    commitOut.scriptPubKey = CScript(commitScript.begin(), commitScript.end());
    const auto existing = std::find_if(coinbaseTx.vout.begin(), coinbaseTx.vout.end(),
                                       [](const CTxOut& txout) {
                                           return IsShaicoinExtCommitmentScript(txout.scriptPubKey);
                                       });
    if (existing == coinbaseTx.vout.end()) {
        coinbaseTx.vout.push_back(std::move(commitOut));
    } else {
        *existing = std::move(commitOut);
    }
    block.vtx[0] = MakeTransactionRef(std::move(coinbaseTx));

    block.hashExtCommitment = commitment;
    block.hashMerkleRoot = BlockMerkleRoot(block);
    return true;
}

inline std::optional<uint256> ExtractExtCommitmentFromCoinbase(const CTransaction& coinbaseTx)
{
    for (const auto& txout : coinbaseTx.vout) {
        const CScript& scriptPubKey = txout.scriptPubKey;
        if (IsShaicoinExtCommitmentScript(scriptPubKey)) {
            uint256 commitment;
            std::copy(scriptPubKey.begin() + 2 + SHAI_EXT_COMMITMENT_PREFIX_LEN,
                      scriptPubKey.begin() + 2 + SHAI_EXT_COMMITMENT_PREFIX_LEN + 32,
                      commitment.begin());
            return commitment;
        }
    }
    return std::nullopt;
}

#endif // SHAICOIN_EXT_PAYLOAD_H
