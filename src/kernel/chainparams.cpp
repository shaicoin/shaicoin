// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <hash.h>
#include <kernel/messagestartchars.h>
#include <logging.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <type_traits>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << nBits << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.vdfSolution = { 0, 1, 2, 5, 3, 4, 7, 6, 9, 8, 10, 13, 11, 12, 15, 14, 17, 16, 18, 21, 19, 20, 23, 22, 25, 24, 26, 29, 27, 28, 31, 30, 33, 32, 34, 37, 35, 36, 39, 38, 41, 40, 42, 45, 43, 44, 47, 46, 49, 48, 50, 53, 51, 52, 55, 54, 57, 56, 58, 61, 59, 60, 63, 62, 65, 64, 66, 69, 67, 68, 71, 70, 73, 72, 74, 77, 75, 76, 79, 78, 81, 80, 82, 85, 83, 84, 87, 86, 89, 88, 90, 93, 91, 92, 95, 94, 97, 96, 98, 101, 99, 100, 103, 102, 105, 104, 106, 109, 107, 108, 111, 110, 113, 112, 114, 117, 115, 116, 119, 118, 121, 120, 122, 125, 123, 124, 127, 126, 129, 128, 130, 133, 131, 132, 135, 134, 137, 136, 138, 141, 139, 140, 143, 142, 145, 144, 146, 149, 147, 148, 151, 150, 153, 152, 154, 157, 155, 156, 159, 158, 161, 160, 162, 165, 163, 164, 167, 166, 169, 168, 170, 173, 171, 172, 175, 174, 177, 176, 178, 181, 179, 180, 183, 182, 185, 184, 186, 189, 187, 188, 191, 190, 193, 192, 194, 197, 195, 196, 199, 198, 201, 200, 202, 205, 203, 204, 207, 206, 209, 208, 210, 213, 211, 212, 215, 214, 217, 216, 218, 221, 219, 220, 223, 222, 225, 224, 226, 229, 227, 228, 231, 230, 233, 232, 234, 237, 235, 236, 239, 238, 241, 240, 242, 245, 243, 244, 247, 246, 249, 248, 250, 253, 251, 252, 255, 254, 257, 256, 258, 261, 259, 260, 263, 262, 265, 264, 266, 269, 267, 268, 271, 270, 273, 272, 274, 277, 275, 276, 279, 278, 281, 280, 282, 285, 283, 284, 287, 286, 289, 288, 290, 293, 291, 292, 295, 294, 297, 296, 298, 301, 299, 300, 303, 302, 305, 304, 306, 309, 307, 308, 311, 310, 313, 312, 314, 317, 315, 316, 319, 318, 321, 320, 322, 325, 323, 324, 327, 326, 329, 328, 330, 333, 331, 332, 335, 334, 337, 336, 338, 341, 339, 340, 343, 342, 345, 344, 346, 349, 347, 348, 351, 350, 353, 352, 354, 357, 355, 356, 359, 358, 361, 360, 362, 365, 363, 364, 367, 366, 369, 368, 370, 373, 371, 372, 375, 374, 377, 376, 378, 381, 379, 380, 383, 382, 385, 384, 386, 389, 387, 388, 391, 390, 393, 392, 394, 397, 395, 396, 399, 398, 401, 400, 402, 405, 403, 404, 407, 406, 409, 408, 410, 413, 411, 412, 415, 414, 417, 416, 418, 421, 419, 420, 423, 422, 425, 424, 426, 429, 427, 428, 431, 430, 433, 432, 434, 437, 435, 436, 439, 438, 441, 440, 442, 445, 443, 444, 447, 446, 449, 448, 450, 453, 451, 452, 455, 454, 457, 456, 458, 461, 459, 460, 463, 462, 465, 464, 466, 469, 467, 468, 471, 470, 473, 472, 474, 477, 475, 476, 479, 478, 481, 480, 482, 485, 483, 484, 487, 486, 489, 488, 490, 493, 491, 492, 495, 494, 497, 496, 498, 501, 499, 500, 503, 502, 505, 504, 506, 509, 507, 508, 511, 510, 513, 512, 514, 517, 515, 516, 519, 518, 521, 520, 522, 525, 523, 524, 527, 526, 529, 528, 530, 533, 531, 532, 535, 534, 537, 536, 538, 541, 539, 540, 543, 542, 545, 544, 546, 549, 547, 548, 551, 550, 553, 552, 554, 557, 555, 556, 559, 558, 561, 560, 562, 565, 563, 564, 567, 566, 569, 568, 570, 573, 571, 572, 575, 574, 577, 576, 578, 581, 579, 580, 583, 582, 585, 584, 586, 589, 587, 588, 591, 590, 593, 592, 594, 597, 595, 596, 599, 598, 601, 600, 602, 605, 603, 604, 607, 606, 609, 608, 610, 613, 611, 612, 615, 614, 617, 616, 618, 621, 619, 620, 623, 622, 625, 624, 626, 629, 627, 628, 631, 630, 633, 632, 634, 637, 635, 636, 639, 638, 641, 640, 642, 645, 643, 644, 647, 646, 649, 648, 650, 653, 651, 652, 655, 654, 657, 656, 658, 661, 659, 660, 663, 662, 665, 664, 666, 669, 667, 668, 671, 670, 673, 672, 674, 677, 675, 676, 679, 678, 681, 680, 682, 685, 683, 684, 687, 686, 689, 688, 690, 693, 691, 692, 695, 694, 697, 696, 698, 701, 699, 700, 703, 702, 705, 704, 706, 709, 707, 708, 711, 710, 713, 712, 714, 717, 715, 716, 719, 718, 721, 720, 722, 725, 723, 724, 727, 726, 729, 728, 730, 733, 731, 732, 735, 734, 737, 736, 738, 741, 739, 740, 743, 742, 745, 744, 746, 749, 747, 748, 751, 750, 753, 752, 754, 757, 755, 756, 759, 758, 761, 760, 762, 765, 763, 764, 767, 766, 769, 768, 770, 773, 771, 772, 775, 774, 777, 776, 778, 781, 779, 780, 783, 782, 785, 784, 786, 789, 787, 788, 791, 790, 793, 792, 794, 797, 795, 796, 799, 798, 801, 800, 802, 805, 803, 804, 807, 806, 809, 808, 810, 813, 811, 812, 815, 814, 817, 816, 818, 821, 819, 820, 823, 822, 825, 824, 826, 829, 827, 828, 831, 830, 833, 832, 834, 837, 835, 836, 839, 838, 841, 840, 842, 845, 843, 844, 847, 846, 849, 848, 850, 853, 851, 852, 855, 854, 857, 856, 858, 861, 859, 860, 863, 862, 865, 864, 866, 869, 867, 868, 871, 870, 873, 872, 874, 877, 875, 876, 879, 878, 881, 880, 882, 885, 883, 884, 887, 886, 889, 888, 890, 893, 891, 892, 895, 894, 897, 896, 898, 901, 899, 900, 903, 902, 905, 904, 906, 909, 907, 908, 911, 910, 913, 912, 914, 917, 915, 916, 919, 918, 921, 920, 922, 925, 923, 924, 927, 926, 929, 928, 930, 933, 931, 932, 935, 934, 937, 936, 938, 941, 939, 940, 943, 942, 945, 944, 946, 949, 947, 948, 951, 950, 953, 952, 954, 957, 955, 956, 959, 958, 961, 960, 962, 965, 963, 964, 967, 966, 969, 968, 970, 973, 971, 972, 975, 974, 977, 976, 978, 981, 979, 980, 983, 982, 985, 984, 986, 989, 987, 988, 991, 990, 993, 992, 994, 997, 995, 996, 999, 998, 1001, 1000, 1002, 1005, 1003, 1004, 1007, 1006, 1009, 1008, 1010, 1013, 1011, 1012, 1015, 1014, 1017, 1016, 1018, 1021, 1019, 1020, 1023, 1022, 1025, 1024, 1026, 1029, 1027, 1028, 1031, 1030, 1033, 1032, 1034, 1037, 1035, 1036, 1039, 1038, 1041, 1040, 1042, 1045, 1043, 1044, 1047, 1046, 1049, 1048, 1050, 1053, 1051, 1052, 1055, 1054, 1057, 1056, 1058, 1061, 1059, 1060, 1063, 1062, 1065, 1064, 1066, 1069, 1067, 1068, 1071, 1070, 1073, 1072, 1074, 1077, 1075, 1076, 1079, 1078, 1081, 1080, 1082, 1085, 1083, 1084, 1087, 1086, 1089, 1088, 1090, 1093, 1091, 1092, 1095, 1094, 1097, 1096, 1098, 1101, 1099, 1100, 1103, 1102, 1105, 1104, 1106, 1109, 1107, 1108, 1111, 1110, 1113, 1112, 1114, 1117, 1115, 1116, 1119, 1118, 1121, 1120, 1122, 1125, 1123, 1124, 1127, 1126, 1129, 1128, 1130, 1133, 1131, 1132, 1135, 1134, 1137, 1136, 1138, 1141, 1139, 1140, 1143, 1142, 1145, 1144, 1146, 1149, 1147, 1148, 1151, 1150, 1153, 1152, 1154, 1157, 1155, 1156, 1159, 1158, 1161, 1160, 1162, 1165, 1163, 1164, 1167, 1166, 1169, 1168, 1170, 1173, 1171, 1172, 1175, 1174, 1177, 1176, 1178, 1181, 1179, 1180, 1183, 1182, 1185, 1184, 1186, 1189, 1187, 1188, 1191, 1190, 1193, 1192, 1194, 1197, 1195, 1196, 1199, 1198, 1201, 1200, 1202, 1205, 1203, 1204, 1207, 1206, 1209, 1208, 1210, 1213, 1211, 1212, 1215, 1214, 1217, 1216, 1218, 1221, 1219, 1220, 1223, 1222, 1225, 1224, 1226, 1229, 1227, 1228, 1231, 1230, 1233, 1232, 1234, 1237, 1236, 1240, 1235, 1238, 1239, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535 };
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Proof-of-work is essentially one-CPU-one-vote";
    const CScript genesisOutputScript = CScript() << ParseHex("046f93d36211501191a15cddf852fed215cd16135c2484832f801f3512e60b3d8b69be5a6b181ad7f18062bdd2d2906a2c90245476f74fffc9ab7af5780f55344b") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network on which people trade goods and services.
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        m_chain_type = ChainType::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.tailEmissionBlockHeight = 888420;
        consensus.script_flag_exceptions.emplace( // BIP16 exception
            uint256S("0x00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"), SCRIPT_VERIFY_NONE);
        consensus.script_flag_exceptions.emplace( // Taproot exception
            uint256S("0x0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"), SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS);
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x005bf9ad68a610dee37ed5548a963ab9727df30f000085d02992ee2aac010c27");
        consensus.BIP65Height = 0; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP66Height = 0; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.CSVHeight = 0; // 000000000000000004a1b34462cb8aeebd5799177f7a29cf28f2d1961716b5b5
        consensus.SegwitHeight = 0; // 0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893
        consensus.MinBIP9WarningHeight = 24; // segwit activation height + miner confirmation window
        consensus.powLimit = uint256S("0x007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 2 * 60;
        consensus.nPowTargetSpacing = 2 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 22; // ~90% of 24
        consensus.nMinerConfirmationWindow = 30; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = 1619222400; // April 24th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = 1628640000; // August 11th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // Approximately November 12th, 2021

        consensus.nMinimumChainWork = uint256S("0");
        consensus.defaultAssumeValid = uint256S("0x005bf9ad68a610dee37ed5548a963ab9727df30f000085d02992ee2aac010c27");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xe4;
        pchMessageStart[1] = 0xbe;
        pchMessageStart[2] = 0x7c;
        pchMessageStart[3] = 0xd1;
        nDefaultPort = 42069;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 600;
        m_assumed_chain_state_size = 10;

        genesis = CreateGenesisBlock(1722343420, 3146876148, 0x1f7fffff, 1, 11 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        std::cout << consensus.hashGenesisBlock.ToString() << std::endl;
        std::cout << genesis.hashMerkleRoot.ToString() << std::endl;
        assert(consensus.hashGenesisBlock == uint256S("0x005bf9ad68a610dee37ed5548a963ab9727df30f000085d02992ee2aac010c27"));
        assert(genesis.hashMerkleRoot == uint256S("0x2a9f2576a15e81773726f78378842567276e3b43860290adfe30d113ca6cef76"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as an addrfetch if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.

        vSeeds.emplace_back("seeder.shaicoin.org.");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,137);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,135);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,117);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "sh";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_main), std::end(chainparams_seed_main));

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                { 0, uint256S("0x005bf9ad68a610dee37ed5548a963ab9727df30f000085d02992ee2aac010c27") },
                //{ 1100, uint256S("0x0000009b16de48bc340022acf3a1da667c4109b8b55face581b69233814935dc") }
            }
        };

        m_assumeutxo_data = {
            // TODO to be specified in a future patch.
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 1100 0000018de0f627acbb7f6a526ec99ff9c9310e43d76ff5403ab3515e27671abd
            .nTime    = 1720751860,
            .nTxCount = 1109,
            .dTxRate  = 0.003946924628092057,
        };
    }
};

/**
 * Testnet (v3): public test network which is reset from time to time.
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        m_chain_type = ChainType::TESTNET;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.tailEmissionBlockHeight = 420480;
        consensus.script_flag_exceptions.emplace( // BIP16 exception
            uint256S("0x00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"), SCRIPT_VERIFY_NONE);
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
        consensus.BIP65Height = 0; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP66Height = 0; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.CSVHeight = 0; // 00000000025e930139bac5c6c31a403776da130831ab85be56578f3fa75369bb
        consensus.SegwitHeight = 0; // 00000000002b980fcd729daaa248fd9316a5200e9b367f4ff2c42453e84201ca
        consensus.MinBIP9WarningHeight = 0; // segwit activation height + miner confirmation window
        consensus.powLimit = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 2 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 22; // 75% for testchains
        consensus.nMinerConfirmationWindow = 24; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = 1619222400; // April 24th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = 1628640000; // August 11th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256S("0");
        consensus.defaultAssumeValid = uint256S("0x000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"); // 2550000

        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x09;
        pchMessageStart[3] = 0x3a;
        nDefaultPort = 18333;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 42;
        m_assumed_chain_state_size = 3;

        genesis = CreateGenesisBlock(1720471420, 2157475185, 0x1f00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        // assert(consensus.hashGenesisBlock == uint256S("0x007a91ae5fb2380bd8da591eccadaa4030bf4f84240089eba2a460bedcc3b723"));
        // assert(genesis.hashMerkleRoot == uint256S("0x5b53a050a9980529aacc59a2e30e15f7540b6021d06da511d87e3e3d0e4f7644"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_test), std::end(chainparams_seed_test));

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {0, uint256S("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")},
            }
        };

        m_assumeutxo_data = {
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 000000000001323071f38f21ea5aae529ece491eadaccce506a59bcc2d968917
            .nTime    = 1703579240,
            .nTxCount = 67845391,
            .dTxRate  = 1.464436832560951,
        };
    }
};

/**
 * Signet: test network with an additional consensus parameter (see BIP325).
 */
class SigNetParams : public CChainParams {
public:
    explicit SigNetParams(const SigNetOptions& options)
    {
        std::vector<uint8_t> bin;
        vSeeds.clear();

        if (!options.challenge) {
            bin = ParseHex("512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae");
            vSeeds.emplace_back("seed.signet.bitcoin.sprovoost.nl.");

            // Hardcoded nodes can be removed once there are more DNS seeds
            vSeeds.emplace_back("178.128.221.177");
            vSeeds.emplace_back("v7ajjeirttkbnt32wpy3c6w3emwnfr3fkla7hpxcfokr3ysd3kqtzmqd.onion:38333");

            consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000000000206e86f08e8");
            consensus.defaultAssumeValid = uint256S("0x0000000870f15246ba23c16e370a7ffb1fc8a3dcf8cb4492882ed4b0e3d4cd26"); // 180000
            m_assumed_blockchain_size = 1;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                // Data from RPC: getchaintxstats 4096 0000000870f15246ba23c16e370a7ffb1fc8a3dcf8cb4492882ed4b0e3d4cd26
                .nTime    = 1706331472,
                .nTxCount = 2425380,
                .dTxRate  = 0.008277759863833788,
            };
        } else {
            bin = *options.challenge;
            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 0;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                0,
                0,
                0,
            };
            LogPrintf("Signet with challenge %s\n", HexStr(bin));
        }

        if (options.seeds) {
            vSeeds = *options.seeds;
        }

        m_chain_type = ChainType::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());
        consensus.tailEmissionBlockHeight = 210000;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256S("00000377ae000000000000000000000000000000000000000000000000000000");
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Activation of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        // message start is defined as the first 4 bytes of the sha256d of the block script
        HashWriter h{};
        h << consensus.signet_challenge;
        uint256 hash = h.GetHash();
        std::copy_n(hash.begin(), 4, pchMessageStart.begin());

        nDefaultPort = 38333;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1598918400, 52613770, 0x1e0377ae, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        // assert(consensus.hashGenesisBlock == uint256S("0x00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"));
        // assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));

        vFixedSeeds.clear();

        m_assumeutxo_data = {
            {
                .height = 160'000,
                .hash_serialized = AssumeutxoHash{uint256S("0xfe0a44309b74d6b5883d246cb419c6221bcccf0b308c9b59b7d70783dbdf928a")},
                .nChainTx = 2289496,
                .blockhash = uint256S("0x0000003ca3c99aff040f2563c2ad8f8ec88bd0fd6b8f0895cfaf1ef90353a62c")
            }
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;
    }
};

/**
 * Regression test: intended for private networks only. Has minimal difficulty to ensure that
 * blocks can be found instantly.
 */
class CRegTestParams : public CChainParams
{
public:
    explicit CRegTestParams(const RegTestOptions& opts)
    {
        m_chain_type = ChainType::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.tailEmissionBlockHeight = 150;
        consensus.BIP34Height = 1; // Always active unless overridden
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;  // Always active unless overridden
        consensus.BIP66Height = 1;  // Always active unless overridden
        consensus.CSVHeight = 1;    // Always active unless overridden
        consensus.SegwitHeight = 0; // Always active unless overridden
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18444;
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        for (const auto& [dep, height] : opts.activation_heights) {
            switch (dep) {
            case Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT:
                consensus.SegwitHeight = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB:
                consensus.BIP34Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_DERSIG:
                consensus.BIP66Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CLTV:
                consensus.BIP65Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CSV:
                consensus.CSVHeight = int{height};
                break;
            }
        }

        for (const auto& [deployment_pos, version_bits_params] : opts.version_bits_parameters) {
            consensus.vDeployments[deployment_pos].nStartTime = version_bits_params.start_time;
            consensus.vDeployments[deployment_pos].nTimeout = version_bits_params.timeout;
            consensus.vDeployments[deployment_pos].min_activation_height = version_bits_params.min_activation_height;
        }

        genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        // assert(consensus.hashGenesisBlock == uint256S("0x0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"));
        // assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();
        vSeeds.emplace_back("dummySeed.invalid.");

        fDefaultConsistencyChecks = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
                {0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")},
            }
        };

        m_assumeutxo_data = {
            {
                .height = 110,
                .hash_serialized = AssumeutxoHash{uint256S("0x6657b736d4fe4db0cbc796789e812d5dba7f5c143764b1b6905612f1830609d1")},
                .nChainTx = 111,
                .blockhash = uint256S("0x696e92821f65549c7ee134edceeeeaaa4105647a3c4fd9f298c0aec0ab50425c")
            },
            {
                // For use by test/functional/feature_assumeutxo.py
                .height = 299,
                .hash_serialized = AssumeutxoHash{uint256S("0xa4bf3407ccb2cc0145c49ebba8fa91199f8a3903daf0883875941497d2493c27")},
                .nChainTx = 334,
                .blockhash = uint256S("0x3bb7ce5eba0be48939b7a521ac1ba9316afee2c7bada3a0cca24188e6d7d96c0")
            },
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "bcrt";
    }
};

std::unique_ptr<const CChainParams> CChainParams::SigNet(const SigNetOptions& options)
{
    return std::make_unique<const SigNetParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::RegTest(const RegTestOptions& options)
{
    return std::make_unique<const CRegTestParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::Main()
{
    return std::make_unique<const CMainParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet()
{
    return std::make_unique<const CTestNetParams>();
}
