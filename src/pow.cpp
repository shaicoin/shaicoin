// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
#include <miner.h>
#include <hash.h>

typedef long long int64;

static const int64 nTargetSpacing = 5 * 60;  // 5 minute block time target
static arith_uint256 bnProofOfWorkLimit(~arith_uint256(0) >> 16);
static const uint8_t sample_window = 4;
static_assert(nTargetSpacing != 0);

int static mapNumber(double x, int in_min, int in_max, int out_min, int out_max) {
  return (x - in_min) * (out_max - out_min) / (in_max - in_min) + out_min;
}

//
//  The catcoin inspiration code had a non typical PID controller calculator
//  so we had to rewrite it from scratch below are the details
//
//  1. Error calculation:
//      error = setpoint - measured_value;
//
//  2. Proportional term (P):
//      P_out = Kp * error;
//
//  3. Integral term (I):
//      integral += error;
//      I_out = Ki * integral;
//
//  4. Derivative term (D):
//      derivative = (error - previous_error) / dt;
//      D_out = Kd * derivative;
//
//  5. Combine the terms:
//      output = P_out + I_out;
//
//  6. Average the output and make asymmetric adjustment (DigiShield Inspired)
//
//  Where:
//  - measured_value: The current value being measured.
//  - setpoint: The desired target value.
//  - Kp: Proportional gain.
//  - Ki: Integral gain.
//  - Kd: Derivative gain.
//  - dt: Time difference between the current and previous measurement.
//  - error: Difference between the measured value and the setpoint.
//  - integral: Accumulated sum of previous errors (for the integral term).
//  - previous_error: The error from the previous time step (for the derivative term).
//  - output: The final control output.
unsigned int static GetNextWorkRequired_PID(const CBlockIndex* pindexLast,
                                            const CBlockHeader *pblock,
                                            const Consensus::Params& params)
{
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);

    double kpGain = 0.716;
    double kiGain = 0.333;
    double kdGain = 0.042;

    int64_t integral_term = 0;
    double u_there = 0;
    int64_t buffer[sample_window];

    const CBlockIndex* pindexFirst = pindexLast;
    int i = sample_window - 1;
    while(i >= 0) {
        buffer[i] = pindexFirst->GetBlockTime();
        pindexFirst = pindexFirst->pprev;
        if(i > 0) {
            i = i - 1;
        } else {
            break;
        }
    }

    for(size_t index = 1; index < sample_window; index++) {
        int64_t time_between_blocks = buffer[index] - buffer[index - 1];
        int64_t time_between_old_blocks = (index == 1) ? 0 : buffer[index - 1] - buffer[index - 2];

        int64_t current_system_error = nTargetSpacing - time_between_blocks;
        int64_t previous_system_error = (index == 1) ? 0 : nTargetSpacing - time_between_old_blocks;
        
        integral_term += current_system_error;

        double p = kpGain * current_system_error;
        double i = kiGain * integral_term;
        double d = (time_between_blocks == 0) ? 0 : kdGain * ((current_system_error - previous_system_error) / time_between_blocks);

        u_there += p + i + d;
    }

    double rounded_value = std::round(u_there / (sample_window - 1));

    if(rounded_value < -42) { // longer than normal
        double max_adjustment = -nTargetSpacing;
        if(rounded_value < max_adjustment) {
            rounded_value = max_adjustment;
        }
        bnNew *= mapNumber(-rounded_value, 42, -max_adjustment, 105, 132);
        bnNew /= 100;
    } else if(rounded_value > 42) { // shorter than normal
        double max_adjustment = nTargetSpacing * 1.24;
        if(rounded_value > max_adjustment) {
            rounded_value = max_adjustment;
        }
        bnNew *= 100;
        bnNew /= mapNumber(rounded_value, 42, max_adjustment, 102, 116);
    }

    if (bnNew > bnProofOfWorkLimit || (bnNew.getdouble() == 0)) {
        bnNew = bnProofOfWorkLimit;
    }

    return bnNew.GetCompact();
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast,
                                 const CBlockHeader *pblock,
                                 const Consensus::Params& params) {
    assert(pindexLast != nullptr);

    if (pindexLast->nHeight <= (sample_window + 1)) {
        return bnProofOfWorkLimit.GetCompact();
    }
    
	return GetNextWorkRequired_PID(pindexLast, pblock, params);
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    arith_uint256 old_target, new_target;
    old_target.SetCompact(old_nbits);
    new_target.SetCompact(new_nbits);

    // Calculate the permitted range
    arith_uint256 max_increase = old_target;
    arith_uint256 max_decrease = old_target;

    max_increase *= 133;
    max_increase /= 100;

    max_decrease *= 100;
    max_decrease /= 117;

    if (new_target > max_increase || new_target < max_decrease) {
        return false;
    }
    return true;
}

bool CheckProofOfWork(uint256 hash,
                      uint256 shaTwoFiftySixHash,
                      unsigned int nBits,
                      uint256 hashRandomX,
                      const std::array<uint16_t, 1992>& vdfSolution,
                      const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit)) {
        return false;
    }

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget) {
        return false;
    }

    // construct RandomX
    uint256 second_hash = (HashWriter{} << shaTwoFiftySixHash).GetSHA256();
    // uint256 randomx_hash = calculate_randomx_hash(shaTwoFiftySixHash.ToString(),
    //                                               second_hash.ToString());
    // if(randomx_hash != hashRandomX) {
    //     return false;
    // }

    // construct VDF Graph
    uint256 graph_construction_hash = second_hash ^ hashRandomX;
    HCGraphUtil util{};
    size_t grid_size = util.getGridSize(graph_construction_hash.ToString());
    std::vector<std::vector<bool>> graph = util.generateGraph(graph_construction_hash, grid_size);

    std::array<uint16_t, 1992> vdf_solution {};
    std::copy(vdfSolution.begin(), vdfSolution.end(), vdf_solution.begin());

    bool found_zero = false;
    for(size_t i = 0; i < 1992; i++) {
        if(vdf_solution[0] == 0) {
            found_zero = true;
            break;
        }
        util.reverse_shift(vdf_solution);
    }
    
    if(found_zero == false) {
        return false;
    }

    // verify the vdf solution
    return util.verifyHamiltonianCycle(graph, vdf_solution);
}
