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
        std::string gridSizeSegment = hash.substr(0, 4);
        unsigned long long gridSize = hexToType<unsigned long long>(gridSizeSegment);
        
        int minGridSize = 512;
        int maxGridSize = GRAPH_SIZE;
        int numSegments = 1480;
        
        double segmentSize = static_cast<double>(maxGridSize - minGridSize) / numSegments;
        int normalizedGridSize = minGridSize + static_cast<int>(gridSize % numSegments * segmentSize);
        
        return normalizedGridSize;
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
        
        if (elapsed > 3000) { // if we have longer than 3 seconds bail
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
        // hmm we are returning -1 in path potentially
        return path;
    }

    void shift(std::array<uint16_t, GRAPH_SIZE>& arr) {
        if (!arr.empty()) {
            std::rotate(arr.rbegin(), arr.rbegin() + 1, arr.rend());
        }
    }

    void reverse_shift(std::array<uint16_t, GRAPH_SIZE>& arr) {
        if (!arr.empty()) {
            std::rotate(arr.begin(), arr.begin() + 1, arr.end());
        }
    }
};

/** Run the miner threads */
void GenerateShaicoins(std::optional<CScript> minerAddress,
                       const CChainParams& chainparams,
                       ChainstateManager& chainman,
                       const CConnman& conman,
                       const CTxMemPool& mempool);

#endif // BITCOIN_MINER_H
