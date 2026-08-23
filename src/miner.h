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
#include <chrono>
#include <ctime>
#include <algorithm>
#include <limits>
#include <type_traits>
#include <unordered_set>
#include <utility>

inline uint64_t libstdcpp_uniform_u64_ab(uint64_t a, uint64_t b, std::mt19937_64& rng) {
    using engine_type = std::mt19937_64;
    using eng_result = engine_type::result_type;
    using user_result = uint64_t;
    using common_type = typename std::common_type<eng_result, user_result>::type;
    static_assert(std::numeric_limits<eng_result>::is_integer && !std::numeric_limits<eng_result>::is_signed);
    const common_type eng_min = engine_type::min();
    const common_type eng_max = engine_type::max();
    const common_type eng_range = eng_max - eng_min;
    if (a > b) {
        std::swap(a, b);
    }
    const common_type user_a = a;
    const common_type user_b = b;
    const common_type user_range = user_b - user_a;
    common_type value;
    if (eng_range > user_range) {
        const common_type user_size = user_range + 1;
        const common_type scaling = eng_range / user_size;
        const common_type limit = user_size * scaling;
        do {
            value = common_type(rng()) - eng_min;
        } while (value >= limit);
        value /= scaling;
    } else {
        value = common_type(rng()) - eng_min;
    }
    return static_cast<user_result>(value + user_a);
}

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

    bool static verifyHamiltonianCycle_V2(const std::vector<std::vector<bool>>& graph,
                                          const std::array<uint16_t, GRAPH_SIZE>& path)
    {
        // Ensure the first path is zero
        if (path[0] != 0) {
            return false;
        }

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

    bool static verifyHamiltonianCycle_V3(const std::vector<std::vector<bool>>& graph,
                                          const std::vector<uint16_t>& path)
    {
        size_t n = graph.size();

        if (path.size() != n) {
            return false;
        }

        if (path.empty()) {
            return false;
        }

        if (path[0] != 0) {
            return false;
        }

        auto it = std::find(path.begin(), path.end(), USHRT_MAX);
        if (it != path.end()) {
            return false;
        }

        std::unordered_set<uint16_t> verticesInPath(path.begin(), path.end());
        if (verticesInPath.size() != n) {
            return false;
        }

        for (size_t i = 1; i < n; ++i) {
            if (!graph[path[i - 1]][path[i]]) {
                return false;
            }
        }

        if (!graph[path[n - 1]][path[0]]) {
            return false;
        }
        
        return true;
    }

    bool static verifyHamiltonianCycle_V4(const std::vector<std::vector<bool>>& graph,
                                          const std::vector<uint16_t>& path)
    {
        size_t n = graph.size();

        if (path.size() != n) {
            return false;
        }

        if (path.empty()) {
            return false;
        }

        if (path[0] != 0) {
            return false;
        }

        auto it = std::find(path.begin(), path.end(), USHRT_MAX);
        if (it != path.end()) {
            return false;
        }

        std::unordered_set<uint16_t> verticesInPath(path.begin(), path.end());
        if (verticesInPath.size() != n) {
            return false;
        }

        for (size_t i = 1; i < n; ++i) {
            if (!graph[path[i - 1]][path[i]]) {
                return false;
            }
        }

        if (!graph[path[n - 1]][path[0]]) {
            return false;
        }

        for (size_t i = 1; i < n - 1; ++i) {
            for (size_t j = i + 1; j < n - 1; ++j) {
                if (graph[path[i - 1]][path[j]] &&
                    graph[path[i]][path[j + 1]] &&
                    path[i] > path[j]) {
                    return false;
                }
            }
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

    uint16_t workerGridSize(const std::string& hash) {
        int min_grid_size = 1892;
        int max_grid_size = 1920;
        std::string grid_size_segment = hash.substr(0, 8);
        unsigned long long grid_size = hexToType<unsigned long long>(grid_size_segment);
        auto grid_size_final = min_grid_size + (grid_size % (max_grid_size - min_grid_size));
        return grid_size_final;
    }

    uint16_t queenBeeGridSize(uint16_t workerSize) {
        return GRAPH_SIZE - workerSize;
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

    std::vector<std::vector<bool>> generateGraph_V3(const uint256& hash,
                                                    uint16_t gridSize,
                                                    uint16_t percentageX10) {
        std::vector<std::vector<bool>> graph(gridSize, std::vector<bool>(gridSize, false));

        uint64_t seed = extractSeedFromHash(hash);

        std::mt19937_64 prng(seed);
        const uint64_t range = 1000;
        const uint64_t threshold = (percentageX10 * range) / 1000;
        for (size_t i = 0; i < gridSize; ++i) {
            for (size_t j = i + 1; j < gridSize; ++j) {
                uint64_t randomValue = libstdcpp_uniform_u64_ab(0, range - 1, prng);
                bool edgeExists = randomValue < threshold;
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
    
    std::vector<uint16_t> findHamiltonianCycle_V3(uint256 graph_hash,
                                                  uint16_t graph_size,
                                                  uint16_t percentageX10,
                                                  size_t timeout) {
        std::vector<uint16_t> path;
        path.reserve(graph_size);
        std::vector<bool> visited(graph_size, false);
        const std::vector<std::vector<bool>> edges = generateGraph_V3(graph_hash, graph_size, percentageX10);

        int start = 0;
        auto startTime = std::chrono::steady_clock::now();

        if (dfs_hamilton_path(start,
                              visited,
                              path,
                              edges,
                              startTime,
                              timeout,
                              graph_size)) {
            return path;
        }

        return {};
    }

    template<typename TimePoint>
    bool dfs_hamilton_path(int current,
                           std::vector<bool>& visited,
                           std::vector<uint16_t>& path,
                           const std::vector<std::vector<bool>>& edges,
                           TimePoint startTime,
                           int timeout,
                           uint16_t graph_size) {
        auto currentTime = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            currentTime - startTime
        ).count();

        if (duration > timeout) {
            return false;
        }
        
        path.push_back(current);
        visited[current] = true;

        size_t path_size = path.size();
        if (path_size == graph_size) {
            if (edges[current][0]) {
                return true;
            }
            visited[current] = false;
            path.pop_back();
            return false;
        }

        for (int next = 0; next < graph_size; ++next) {
            if (edges[current][next] && !visited[next]) {
                if (dfs_hamilton_path(next,
                                      visited,
                                      path,
                                      edges,
                                      startTime,
                                      timeout,
                                      graph_size)) {
                    return true;
                }
            }
        }

        visited[current] = false;
        path.pop_back();
        return false;
    }
};

void StopMining();

extern std::atomic<bool> g_mine_require_peers;

/** Run the miner threads */
void GenerateShaicoins(std::optional<CScript> minerAddress,
                       const CChainParams& chainparams,
                       ChainstateManager& chainman,
                       const CConnman& conman,
                       const CTxMemPool& mempool,
                       size_t nThreads = 0);

#endif // BITCOIN_MINER_H
