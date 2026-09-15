// Copyright (c) 2017-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <index/txindex.h>

#include <clientversion.h>
#include <common/args.h>
#include <index/disktxpos.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <primitives/legacy_block.h>
#include <validation.h>

constexpr uint8_t DB_TXINDEX{'t'};

std::unique_ptr<TxIndex> g_txindex;


/** Access to the txindex database (indexes/txindex/) */
class TxIndex::DB : public BaseIndex::DB
{
public:
    explicit DB(size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    /// Read the disk location of the transaction data with the given hash. Returns false if the
    /// transaction hash is not indexed.
    bool ReadTxPos(const uint256& txid, CDiskTxPos& pos) const;

    /// Write a batch of transaction positions to the DB.
    [[nodiscard]] bool WriteTxs(const std::vector<std::pair<uint256, CDiskTxPos>>& v_pos);
};

TxIndex::DB::DB(size_t n_cache_size, bool f_memory, bool f_wipe) :
    BaseIndex::DB(gArgs.GetDataDirNet() / "indexes" / "txindex", n_cache_size, f_memory, f_wipe)
{}

bool TxIndex::DB::ReadTxPos(const uint256 &txid, CDiskTxPos& pos) const
{
    return Read(std::make_pair(DB_TXINDEX, txid), pos);
}

bool TxIndex::DB::WriteTxs(const std::vector<std::pair<uint256, CDiskTxPos>>& v_pos)
{
    CDBBatch batch(*this);
    for (const auto& tuple : v_pos) {
        batch.Write(std::make_pair(DB_TXINDEX, tuple.first), tuple.second);
    }
    return WriteBatch(batch);
}

TxIndex::TxIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, bool f_memory, bool f_wipe)
    : BaseIndex(std::move(chain), "txindex"), m_db(std::make_unique<TxIndex::DB>(n_cache_size, f_memory, f_wipe))
{}

TxIndex::~TxIndex() = default;

bool TxIndex::CustomAppend(const interfaces::BlockInfo& block)
{
    // Exclude genesis block transaction because outputs are not spendable.
    if (block.height == 0) return true;

    assert(block.data);
    CDiskTxPos pos({block.file_number, block.data_pos}, GetSizeOfCompactSize(block.data->vtx.size()));
    std::vector<std::pair<uint256, CDiskTxPos>> vPos;
    vPos.reserve(block.data->vtx.size());
    for (const auto& tx : block.data->vtx) {
        vPos.emplace_back(tx->GetHash(), pos);
        pos.nTxOffset += ::GetSerializeSize(TX_WITH_WITNESS(*tx));
    }
    return m_db->WriteTxs(vPos);
}

BaseIndex::DB& TxIndex::GetDB() const { return *m_db; }

bool TxIndex::FindTx(const uint256& tx_hash, uint256& block_hash, CTransactionRef& tx) const
{
    CDiskTxPos postx;
    if (!m_db->ReadTxPos(tx_hash, postx)) {
        return false;
    }

    AutoFile file{m_chainstate->m_blockman.OpenBlockFile(postx, true)};
    if (file.IsNull()) {
        LogError("%s: OpenBlockFile failed\n", __func__);
        return false;
    }
    // A block's on-disk header size depends on the block's OWN nTime: a legacy VDF header is
    // 4096 bytes, while a RandomX header (from nRandomXV2Time onward) is 112. CustomAppend()
    // above records nTxOffset relative to the END of that header, so the header must be
    // consumed in its real format before seeking.
    //
    // Reading it unconditionally as a CBlockHeader consumes only 112 bytes, which leaves the
    // file position 3984 bytes short for every legacy block: the seek below then lands inside
    // vdfSolution, the txid check fails, and FindTx() returns false for EVERY pre-fork
    // transaction (surfacing as "No such mempool or blockchain transaction" from
    // getrawtransaction, even with -txindex=1 fully synced). The block hash derived from such
    // a misread header is garbage too.
    //
    // Probe nTime first and read the header in its real format, exactly as
    // BlockManager::ReadBlock() does. This is a READ-side fix only: the on-disk txindex
    // records already store the correct offsets, so no -reindex is required.
    uint256 header_hash;
    try {
        CBlockHeader probe;
        file >> probe;
        file.seek(-static_cast<int64_t>(GetSerializeSize(probe)), SEEK_CUR);
        if (probe.nTime < m_chainstate->m_chainman.GetConsensus().nRandomXV2Time) {
            CLegacyBlockHeader legacy_header;
            file >> legacy_header;
            header_hash = legacy_header.GetHash();
        } else {
            CBlockHeader header;
            file >> header;
            header_hash = header.GetHash();
        }
        file.seek(postx.nTxOffset, SEEK_CUR);
        file >> TX_WITH_WITNESS(tx);
    } catch (const std::exception& e) {
        LogError("%s: Deserialize or I/O error - %s\n", __func__, e.what());
        return false;
    }
    if (tx->GetHash() != tx_hash) {
        LogError("%s: txid mismatch\n", __func__);
        return false;
    }
    block_hash = header_hash;
    return true;
}
