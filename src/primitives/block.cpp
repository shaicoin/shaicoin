// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>
#include <primitives/legacy_block.h>

#include <hash.h>
#include <tinyformat.h>

CBlockHeader::CBlockHeader(const CLegacyBlockHeader& legacy)
    : nVersion(legacy.nVersion),
      hashPrevBlock(legacy.hashPrevBlock),
      hashMerkleRoot(legacy.hashMerkleRoot),
      nTime(legacy.nTime),
      nBits(legacy.nBits),
      nNonce(legacy.nNonce)
{
    // Legacy headers have no extension commitment. Set it explicitly to null so
    // a converted header never carries an indeterminate value into the block
    // index / preimage.
    hashExtCommitment.SetNull();
}

CBlock::CBlock(const CLegacyBlock& legacy)
{
    SetNull();
    nVersion = legacy.nVersion;
    hashPrevBlock = legacy.hashPrevBlock;
    hashMerkleRoot = legacy.hashMerkleRoot;
    nTime = legacy.nTime;
    nBits = legacy.nBits;
    nNonce = legacy.nNonce;
    vtx = legacy.vtx;
}

uint256 CBlockHeader::GetHash() const
{
    return (HashWriter{} << *this).GetSHA256();
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
