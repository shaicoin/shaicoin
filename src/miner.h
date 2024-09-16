// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MINER_H
#define BITCOIN_MINER_H

#include "primitives/block.h"
#include <validation.h>
#include <stdint.h>
#include <net.h>
#include <random>

using Clock = std::chrono::high_resolution_clock;

class CBlockIndex;
class CChainParams;
class CReserveKey;
class CScript;
class CWallet;
namespace Consensus { struct Params; };

class HCGraphUtil {
    std::chrono::time_point<Clock> startTime;

    template<typename T>
    T hexToType(const std::string& hexString)
    {
        static_assert(std::is_integral<T>::value, "Integral type required.");
        T number;
        std::stringstream ss;
        ss << std::hex << hexString;
        ss >> number;
        return number;
    }

    uint64_t extractSeedFromHash(const uint256& hash)
    {
        return hash.GetUint64(0);
    }

    public: 


    bool static verifyHamiltonianCycle(const std::vector<std::vector<bool>>& graph,
                                       const std::array<uint16_t, GRAPH_SIZE>& path)
    {
        size_t path_size = 0;
        auto it = std::find(path.begin(), path.end(), USHRT_MAX);
        if (it != path.end()) {
            path_size = std::distance(path.begin(), it);
        }

        size_t n = graph.size();

        // Check if path contains all vertices exactly once
        if (path_size != n) {
            return false;
        }
        std::unordered_set<uint16_t> verticesInPath(path.begin(), path.begin() + path_size);
        if (verticesInPath.size() != n) {
            return false;
        }

        // Check if the path forms a cycle
        for (size_t i = 1; i < n; ++i) {
            if (!graph[path[i - 1]][path[i]]) {
                return false;
            }
        }

        // Check if there's an edge from the last to the first vertex to form a cycle
        if (!graph[path[n - 1]][path[0]]) {
            return false;
        }
        
        return true;
    }

    uint16_t getGridSize(const std::string& hash)
    {
        int minGridSize = 512;
        int maxGridSize = GRAPH_SIZE;
        std::string gridSizeSegment = hash.substr(0, 8);
        unsigned long long gridSize = hexToType<unsigned long long>(gridSizeSegment);

        // Normalize gridSize to within the range
        int normalizedGridSize = minGridSize + (gridSize % (maxGridSize - minGridSize));

        // Adjust to hit maxGridSize more frequently
        if ((gridSize % 8) == 0)
        {
            normalizedGridSize = maxGridSize;
        }
        return normalizedGridSize;
    }

    uint16_t getGridSize_V2(const std::string& hash)
    {
        int min_grid_size = 2000;
        int max_grid_size = GRAPH_SIZE;
        std::string grid_size_segment = hash.substr(0, 8);
        unsigned long long grid_size = hexToType<unsigned long long>(grid_size_segment);
        auto grid_size_final = min_grid_size + (grid_size % (max_grid_size - min_grid_size));
        if(grid_size_final > GRAPH_SIZE) {
            grid_size_final = GRAPH_SIZE;
        }
        return grid_size_final;
    }

    std::vector<std::vector<bool>> generateGraph(const uint256& hash,
                                                 uint16_t gridSize)
    {
        std::vector<std::vector<bool>> graph(gridSize, std::vector<bool>(gridSize, false));
        int hashLength = hash.size();
        std::string ref_hash_index = hash.ToString();
        for (size_t i = 0; i < gridSize; ++i) {
            for (int j = i + 1; j < gridSize; ++j) {
                int hashIndex = (i * gridSize + j) * 2 % hashLength;
                uint8_t ch1 = ref_hash_index[hashIndex % hashLength];
                uint8_t ch2 = ref_hash_index[(hashIndex + 1) % hashLength];

                unsigned int edgeValue = ((isdigit(ch1) ? ch1 - '0' : ch1 - 'a' + 10) << 4) +
                                        (isdigit(ch2) ? ch2 - '0' : ch2 - 'a' + 10);
                if (edgeValue < 128) {
                    graph[i][j] = graph[j][i] = true;
                }
            }
        }
        return graph;
    }

    std::vector<std::vector<bool>> generateGraph_V2(const uint256& hash,
                                                 uint16_t gridSize)
    {
        std::vector<std::vector<bool>> graph(gridSize, std::vector<bool>(gridSize, false));
        size_t numEdges = (gridSize * (gridSize - 1)) / 2;
        size_t bitsNeeded = numEdges; // One bit per edge

        // Extract seed from hash
        uint64_t seed = extractSeedFromHash(hash);

        // Initialize PRNG with seed
        std::mt19937_64 prng;
        prng.seed(seed);

        // Generate bitsNeeded bits
        std::vector<bool> bitStream;
        bitStream.reserve(bitsNeeded);

        for (size_t i = 0; i < bitsNeeded; ++i) {
            uint32_t randomBits = prng();
            // Extract bits from randomBits
            for (int j = 31; j >= 0 && bitStream.size() < bitsNeeded; --j) {
                bool bit = (randomBits >> j) & 1;
                bitStream.push_back(bit);
            }
        }

        // Fill the adjacency matrix
        size_t bitIndex = 0;
        for (size_t i = 0; i < gridSize; ++i) {
            for (size_t j = i + 1; j < gridSize; ++j) {
                bool edgeExists = bitStream[bitIndex++];
                graph[i][j] = graph[j][i] = edgeExists;
            }
        }
        return graph;
    }

    bool isSafe(int v,
                const std::vector<std::vector<bool>>& graph,
                std::vector<uint16_t>& path,
                int pos)
    {
        if (!graph[path[pos - 1]][v]) {
            return false;
        }

        for (int i = 0; i < pos; i++) {
            if (path[i] == v) {
                return false;
            }
        }

        return true;
    }

    bool hamiltonianCycleUtil(std::vector<std::vector<bool>>& graph,
                              std::vector<uint16_t>& path,
                              size_t pos)
    {
        auto currentTime = Clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - startTime).count();
        
        if (elapsed > 1000) { // if we have longer than 1 seconds bail
            return false;
        }

        if (pos == graph.size()) {
            if (graph[path[pos - 1]][path[0]]) {
                return true;
            } else {
                return false;
            }
        }

        for (size_t v = 1; v < graph.size(); v++) {
            if (isSafe(v, graph, path, pos)) {
                path[pos] = v;

                if (hamiltonianCycleUtil(graph, path, pos + 1)) {
                    return true;
                }

                path[pos] = -1;
            }
        }

        return false;
    }

    std::vector<uint16_t> findHamiltonianCycle(uint256 graph_hash)
    {
        std::vector<std::vector<bool>> graph = generateGraph(graph_hash, getGridSize(graph_hash.ToString()));
        std::vector<uint16_t> path(graph.size(), -1);

        path[0] = 0;
        startTime = Clock::now();

        if (!hamiltonianCycleUtil(graph, path, 1)) {
            return {};
        }
        return path;
    }

    std::vector<uint16_t> findHamiltonianCycle_V2(uint256 graph_hash)
    {
        std::vector<std::vector<bool>> graph = generateGraph_V2(graph_hash, getGridSize_V2(graph_hash.ToString()));
        std::vector<uint16_t> path(graph.size(), -1);

        path[0] = 0;
        startTime = Clock::now();

        if (!hamiltonianCycleUtil(graph, path, 1)) {
            return {};
        }
        return path;
    }
};

/** Run the miner threads */
void GenerateShaicoins(std::optional<CScript> minerAddress,
                       const CChainParams& chainparams,
                       ChainstateManager& chainman,
                       const CConnman& conman,
                       const CTxMemPool& mempool);

#endif // BITCOIN_MINER_H
