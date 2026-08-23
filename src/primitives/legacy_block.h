// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_LEGACY_BLOCK_H
#define BITCOIN_PRIMITIVES_LEGACY_BLOCK_H

#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>
#include <util/time.h>
#include <pow.h>

class CLegacyBlockHeader
{
public:
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
    std::array<uint16_t, GRAPH_SIZE> vdfSolution;

    CLegacyBlockHeader()
    {
        SetNull();
    }

    SERIALIZE_METHODS(CLegacyBlockHeader, obj) { READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce, obj.vdfSolution); }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        vdfSolution.fill(USHRT_MAX);
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    [[nodiscard]] uint256 GetHash() const;
    [[nodiscard]] uint256 GetSHA256() const;

    NodeSeconds Time() const
    {
        return NodeSeconds{std::chrono::seconds{nTime}};
    }

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};


class CLegacyBlock : public CLegacyBlockHeader
{
public:
    std::vector<CTransactionRef> vtx;

    mutable bool fChecked;
    mutable bool m_checked_witness_commitment{false};
    mutable bool m_checked_merkle_root{false};

    CLegacyBlock()
    {
        SetNull();
    }

    CLegacyBlock(const CLegacyBlockHeader &header)
    {
        SetNull();
        *(static_cast<CLegacyBlockHeader*>(this)) = header;
    }

    SERIALIZE_METHODS(CLegacyBlock, obj)
    {
        READWRITE(AsBase<CLegacyBlockHeader>(obj), obj.vtx);
    }

    void SetNull()
    {
        CLegacyBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
        m_checked_witness_commitment = false;
        m_checked_merkle_root = false;
    }

    CLegacyBlockHeader GetBlockHeader() const
    {
        CLegacyBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        block.vdfSolution    = vdfSolution;
        return block;
    }

    std::string ToString() const;
};

#endif // BITCOIN_PRIMITIVES_LEGACY_BLOCK_H
