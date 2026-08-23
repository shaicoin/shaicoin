// Copyright (c) 2024 The Shaicoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SHAICOIN_EXT_PAYLOAD_H
#define SHAICOIN_EXT_PAYLOAD_H

#include <serialize.h>
#include <uint256.h>
#include <hash.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
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

inline std::optional<uint256> ExtractExtCommitmentFromCoinbase(const CTransaction& coinbaseTx)
{
    for (const auto& txout : coinbaseTx.vout) {
        const CScript& scriptPubKey = txout.scriptPubKey;
        if (scriptPubKey.size() >= 1 + 1 + SHAI_EXT_COMMITMENT_PREFIX_LEN + 32 &&
            scriptPubKey[0] == OP_RETURN) {
            size_t push_len = scriptPubKey[1];
            if (push_len == SHAI_EXT_COMMITMENT_PREFIX_LEN + 32 &&
                scriptPubKey.size() >= 2 + push_len) {
                if (std::equal(std::begin(SHAI_EXT_COMMITMENT_PREFIX),
                               std::end(SHAI_EXT_COMMITMENT_PREFIX),
                               scriptPubKey.begin() + 2)) {
                    uint256 commitment;
                    std::copy(scriptPubKey.begin() + 2 + SHAI_EXT_COMMITMENT_PREFIX_LEN,
                              scriptPubKey.begin() + 2 + SHAI_EXT_COMMITMENT_PREFIX_LEN + 32,
                              commitment.begin());
                    return commitment;
                }
            }
        }
    }
    return std::nullopt;
}

#endif // SHAICOIN_EXT_PAYLOAD_H
