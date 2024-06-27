// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>

uint256 CBlockHeader::GetHash() const
{
    return (HashWriter{} << vdfSolution).GetSHA256();
}

uint256 CBlockHeader::GetSHA256() const
{   
    CBlockHeader no_vdf_randomx {};
    no_vdf_randomx.nVersion = nVersion;
    no_vdf_randomx.hashPrevBlock = hashPrevBlock;
    no_vdf_randomx.hashMerkleRoot = hashMerkleRoot;
    no_vdf_randomx.nTime = nTime;
    no_vdf_randomx.nBits = nBits;
    no_vdf_randomx.nNonce = nNonce;
    no_vdf_randomx.hashRandomX.SetNull();
    no_vdf_randomx.vdfSolution.fill(USHRT_MAX); 
    return (HashWriter{} << no_vdf_randomx).GetSHA256();
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
