// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <node/miner.h>
#include <pow.h>
#include <primitives/block.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>
#include <test/util/setup_common.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>

#include <limits>
#include <vector>

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

BOOST_AUTO_TEST_CASE(postfork_timestamp_must_strictly_increase)
{
    const auto& consensus = Params().GetConsensus();

    // Pre-v4/VDF blocks retain the historic MTP-only timestamp rule.
    CBlockIndex legacy_parent;
    legacy_parent.nTime = consensus.nRandomXV2Time - 1;
    legacy_parent.vdfSolution.fill(0);
    CBlockHeader legacy_candidate;
    legacy_candidate.nTime = legacy_parent.nTime - 2;
    BOOST_CHECK(IsPostForkTimestampMonotonic(legacy_candidate, legacy_parent, consensus));

    CBlockHeader v4_parent_header;
    v4_parent_header.nTime = consensus.nRandomXV2Time + 1000;
    CBlockIndex v4_parent{v4_parent_header};

    CBlockHeader candidate;
    candidate.nTime = v4_parent_header.nTime - 2;
    BOOST_CHECK(!IsPostForkTimestampMonotonic(candidate, v4_parent, consensus));

    candidate.nTime = v4_parent_header.nTime;
    BOOST_CHECK(!IsPostForkTimestampMonotonic(candidate, v4_parent, consensus));

    candidate.nTime = v4_parent_header.nTime + 1;
    BOOST_CHECK(IsPostForkTimestampMonotonic(candidate, v4_parent, consensus));
}

BOOST_AUTO_TEST_CASE(postfork_template_time_must_exceed_parent)
{
    auto consensus = Params().GetConsensus();
    consensus.nRandomXV2Time = 1;

    // Keep MTP below the direct parent to model a parent that is a few seconds
    // ahead of the local clock. This is valid under the historic MTP rule but
    // must still produce parent + 1 for a v4 template.
    std::vector<CBlockIndex> chain(CBlockIndex::nMedianTimeSpan);
    for (size_t i = 0; i < chain.size(); ++i) {
        chain[i].nTime = 100;
        chain[i].vdfSolution.fill(USHRT_MAX);
        if (i > 0) chain[i].pprev = &chain[i - 1];
    }
    CBlockIndex& parent = chain.back();
    parent.nTime = 200;

    SetMockTime(150);
    CBlockHeader v4_template;
    node::UpdateTime(&v4_template, consensus, &parent);
    BOOST_CHECK_EQUAL(v4_template.nTime, 201U);

    // The legacy path remains MTP/clock based; no direct-parent constraint is
    // imposed before v4 activation.
    auto legacy_consensus = consensus;
    legacy_consensus.nRandomXV2Time = std::numeric_limits<uint32_t>::max();
    parent.vdfSolution.fill(0);
    CBlockHeader legacy_template;
    node::UpdateTime(&legacy_template, legacy_consensus, &parent);
    BOOST_CHECK_EQUAL(legacy_template.nTime, 150U);
    SetMockTime(0);
}

BOOST_AUTO_TEST_SUITE_END()
