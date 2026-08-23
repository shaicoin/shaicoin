// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/params.h>
#include <pow.h>
#include <primitives/block.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

int GetRandomXKeyBlockHeight(int height);

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(randomx_key_schedule_boundaries)
{
    BOOST_CHECK_EQUAL(GetRandomXKeyBlockHeight(0), 0);
    BOOST_CHECK_EQUAL(GetRandomXKeyBlockHeight(63), 0);
    BOOST_CHECK_EQUAL(GetRandomXKeyBlockHeight(64), 0);
    BOOST_CHECK_EQUAL(GetRandomXKeyBlockHeight(65), 0);
    BOOST_CHECK_EQUAL(GetRandomXKeyBlockHeight(2111), 0);
    BOOST_CHECK_EQUAL(GetRandomXKeyBlockHeight(2112), 2048);
    BOOST_CHECK_EQUAL(GetRandomXKeyBlockHeight(2113), 2048);
}

BOOST_AUTO_TEST_CASE(postfork_header_serialization_roundtrip)
{
    CBlockHeader h;
    h.nVersion = 4;
    h.hashPrevBlock = uint256(1);
    h.hashMerkleRoot = uint256(2);
    h.nTime = 1783652608;
    h.nBits = 0x1f0fffff;
    h.nNonce = 12345;
    h.hashExtCommitment = uint256(3);

    DataStream ss;
    ss << h;

    BOOST_CHECK_EQUAL(ss.size(), 112U);

    CBlockHeader d;
    ss >> d;

    BOOST_CHECK(d.GetHash() == h.GetHash());
    BOOST_CHECK(RandomXPreimageHash(d) == RandomXPreimageHash(h));
    BOOST_CHECK(d.hashExtCommitment == h.hashExtCommitment);
}

BOOST_AUTO_TEST_CASE(randomx_target_decode_rejects_bad_compact)
{
    CBlockHeader h;
    h.nBits = 0;
    const auto err = CheckProofOfWorkRandomXDetailed(h, 100, nullptr, Params().GetConsensus(), nullptr, nullptr, nullptr, nullptr, nullptr);
    BOOST_CHECK(err == RandomXPoWError::BAD_TARGET);
}

BOOST_AUTO_TEST_SUITE_END()
