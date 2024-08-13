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
    genesis.vdfSolution = { 0, 2, 1, 4, 6, 5, 8, 3, 10, 7, 12, 11, 9, 16, 13, 18, 15, 14, 20, 17, 22, 21, 24, 19, 26, 23, 28, 27, 25, 32, 29, 34, 31, 30, 36, 33, 38, 37, 40, 35, 42, 39, 44, 43, 41, 48, 45, 50, 47, 46, 52, 49, 54, 53, 56, 51, 58, 55, 60, 59, 57, 64, 61, 66, 63, 62, 68, 65, 70, 69, 72, 67, 74, 71, 76, 75, 73, 80, 77, 82, 79, 78, 84, 81, 86, 85, 88, 83, 90, 87, 92, 91, 89, 96, 93, 98, 95, 94, 100, 97, 102, 101, 104, 99, 106, 103, 108, 107, 105, 112, 109, 114, 111, 110, 116, 113, 118, 117, 120, 115, 122, 119, 124, 123, 121, 128, 125, 130, 127, 126, 132, 129, 134, 133, 136, 131, 138, 135, 140, 139, 137, 144, 141, 146, 143, 142, 148, 145, 150, 149, 152, 147, 154, 151, 156, 155, 153, 160, 157, 162, 159, 158, 164, 161, 166, 165, 168, 163, 170, 167, 172, 171, 169, 176, 173, 178, 175, 174, 180, 177, 182, 181, 184, 179, 186, 183, 188, 187, 185, 192, 189, 194, 191, 190, 196, 193, 198, 197, 200, 195, 202, 199, 204, 203, 201, 208, 205, 210, 207, 206, 212, 209, 214, 213, 216, 211, 218, 215, 220, 219, 217, 224, 221, 226, 223, 222, 228, 225, 230, 229, 232, 227, 234, 231, 236, 235, 233, 240, 237, 242, 239, 238, 244, 241, 246, 245, 248, 243, 250, 247, 252, 251, 249, 256, 253, 258, 255, 254, 260, 257, 262, 261, 264, 259, 266, 263, 268, 267, 265, 272, 269, 274, 271, 270, 276, 273, 278, 277, 280, 275, 282, 279, 284, 283, 281, 288, 285, 290, 287, 286, 292, 289, 294, 293, 296, 291, 298, 295, 300, 299, 297, 304, 301, 306, 303, 302, 308, 305, 310, 309, 312, 307, 314, 311, 316, 315, 313, 320, 317, 322, 319, 318, 324, 321, 326, 325, 328, 323, 330, 327, 332, 331, 329, 336, 333, 338, 335, 334, 340, 337, 342, 341, 344, 339, 346, 343, 348, 347, 345, 352, 349, 354, 351, 350, 356, 353, 358, 357, 360, 355, 362, 359, 364, 363, 361, 368, 365, 370, 367, 366, 372, 369, 374, 373, 376, 371, 378, 375, 380, 379, 377, 384, 381, 386, 383, 382, 388, 385, 390, 389, 392, 387, 394, 391, 396, 395, 393, 400, 397, 402, 399, 398, 404, 401, 406, 405, 408, 403, 410, 407, 412, 411, 409, 416, 413, 418, 415, 414, 420, 417, 422, 421, 424, 419, 426, 423, 428, 427, 425, 432, 429, 434, 431, 430, 436, 433, 438, 437, 440, 435, 442, 439, 444, 443, 441, 448, 445, 450, 447, 446, 452, 449, 454, 453, 456, 451, 458, 455, 460, 459, 457, 464, 461, 466, 463, 462, 468, 465, 470, 469, 472, 467, 474, 471, 476, 475, 473, 480, 477, 482, 479, 478, 484, 481, 486, 485, 488, 483, 490, 487, 492, 491, 489, 496, 493, 498, 495, 494, 500, 497, 502, 501, 504, 499, 506, 503, 508, 507, 505, 512, 509, 514, 511, 510, 516, 513, 518, 517, 520, 515, 522, 519, 524, 523, 521, 528, 525, 530, 527, 526, 532, 529, 534, 533, 536, 531, 538, 535, 540, 539, 537, 544, 541, 546, 543, 542, 548, 545, 550, 549, 552, 547, 554, 551, 556, 555, 553, 560, 557, 562, 559, 558, 564, 561, 566, 565, 568, 563, 570, 567, 572, 571, 569, 576, 573, 578, 575, 574, 580, 577, 582, 581, 584, 579, 586, 583, 588, 587, 585, 592, 589, 594, 591, 590, 596, 593, 598, 597, 600, 595, 602, 599, 604, 603, 601, 608, 605, 610, 607, 606, 612, 609, 614, 613, 616, 611, 618, 615, 620, 619, 617, 624, 621, 626, 623, 622, 628, 625, 630, 629, 632, 627, 634, 631, 636, 635, 633, 640, 637, 642, 639, 638, 644, 641, 646, 645, 648, 643, 650, 647, 652, 651, 649, 656, 653, 658, 655, 654, 660, 657, 662, 661, 664, 659, 666, 663, 668, 667, 665, 672, 669, 674, 671, 670, 676, 673, 678, 677, 680, 675, 682, 679, 684, 683, 681, 688, 685, 690, 687, 686, 692, 689, 694, 693, 696, 691, 698, 695, 700, 699, 697, 704, 701, 706, 703, 702, 708, 705, 710, 709, 712, 707, 714, 711, 716, 715, 713, 720, 717, 722, 719, 718, 724, 721, 726, 725, 728, 723, 730, 727, 732, 731, 729, 736, 733, 738, 735, 734, 740, 737, 742, 741, 744, 739, 746, 743, 748, 747, 745, 752, 749, 754, 751, 750, 756, 753, 758, 757, 760, 755, 762, 759, 764, 763, 761, 768, 765, 770, 767, 766, 772, 769, 774, 773, 776, 771, 778, 775, 780, 779, 777, 784, 781, 786, 783, 782, 788, 785, 790, 789, 792, 787, 794, 791, 796, 795, 793, 800, 797, 802, 799, 798, 804, 801, 806, 805, 808, 803, 810, 807, 812, 811, 809, 816, 813, 818, 815, 814, 820, 817, 822, 821, 824, 819, 826, 823, 828, 827, 825, 832, 829, 834, 831, 830, 836, 833, 838, 837, 840, 835, 842, 839, 844, 843, 841, 848, 845, 850, 847, 846, 852, 849, 854, 853, 856, 851, 858, 855, 860, 859, 857, 864, 861, 866, 863, 862, 868, 865, 870, 869, 872, 867, 874, 871, 876, 875, 873, 880, 877, 882, 879, 878, 884, 881, 886, 885, 888, 883, 890, 887, 892, 891, 889, 896, 893, 898, 895, 894, 900, 897, 902, 901, 904, 899, 906, 903, 908, 907, 905, 912, 909, 914, 911, 910, 916, 913, 918, 917, 920, 915, 922, 919, 924, 923, 921, 928, 925, 930, 927, 926, 932, 929, 934, 933, 936, 931, 938, 935, 940, 939, 937, 944, 941, 946, 943, 942, 948, 945, 950, 949, 952, 947, 954, 951, 956, 955, 953, 960, 957, 962, 959, 958, 964, 961, 966, 965, 968, 963, 970, 967, 972, 971, 969, 976, 973, 978, 975, 974, 980, 977, 982, 981, 984, 979, 986, 983, 988, 987, 985, 992, 989, 994, 991, 990, 996, 993, 998, 997, 1000, 995, 1002, 999, 1004, 1003, 1001, 1008, 1005, 1010, 1007, 1006, 1012, 1009, 1014, 1013, 1016, 1011, 1018, 1015, 1020, 1019, 1017, 1024, 1021, 1026, 1023, 1022, 1028, 1025, 1030, 1029, 1032, 1027, 1034, 1031, 1036, 1035, 1033, 1040, 1037, 1042, 1039, 1038, 1044, 1041, 1046, 1045, 1048, 1043, 1050, 1047, 1052, 1051, 1049, 1056, 1053, 1058, 1055, 1054, 1060, 1057, 1062, 1061, 1064, 1059, 1066, 1063, 1068, 1067, 1065, 1072, 1069, 1074, 1071, 1070, 1076, 1073, 1078, 1077, 1080, 1075, 1082, 1079, 1084, 1083, 1081, 1088, 1085, 1090, 1087, 1086, 1092, 1089, 1094, 1093, 1096, 1091, 1098, 1095, 1100, 1099, 1097, 1104, 1101, 1106, 1103, 1102, 1108, 1105, 1110, 1109, 1112, 1107, 1114, 1111, 1116, 1115, 1113, 1120, 1117, 1122, 1119, 1118, 1124, 1121, 1126, 1125, 1128, 1123, 1130, 1127, 1132, 1131, 1129, 1136, 1133, 1138, 1135, 1134, 1140, 1137, 1142, 1141, 1144, 1139, 1146, 1143, 1148, 1147, 1145, 1152, 1149, 1154, 1151, 1150, 1156, 1153, 1158, 1157, 1160, 1155, 1162, 1159, 1164, 1163, 1161, 1168, 1165, 1170, 1167, 1166, 1172, 1169, 1174, 1173, 1176, 1171, 1178, 1175, 1180, 1179, 1177, 1184, 1181, 1186, 1183, 1182, 1188, 1185, 1190, 1189, 1192, 1187, 1194, 1191, 1196, 1195, 1193, 1200, 1197, 1202, 1199, 1198, 1204, 1201, 1206, 1205, 1208, 1203, 1210, 1207, 1212, 1211, 1209, 1216, 1213, 1218, 1215, 1214, 1220, 1217, 1222, 1221, 1224, 1219, 1226, 1223, 1228, 1227, 1225, 1232, 1229, 1234, 1231, 1230, 1236, 1233, 1238, 1237, 1240, 1235, 1242, 1239, 1244, 1243, 1241, 1248, 1245, 1250, 1247, 1246, 1252, 1249, 1254, 1253, 1256, 1251, 1258, 1255, 1260, 1259, 1257, 1264, 1261, 1266, 1263, 1262, 1268, 1265, 1270, 1269, 1272, 1267, 1274, 1271, 1276, 1275, 1273, 1280, 1277, 1282, 1279, 1278, 1284, 1281, 1286, 1285, 1288, 1283, 1290, 1287, 1292, 1291, 1289, 1296, 1293, 1298, 1295, 1294, 1300, 1297, 1302, 1301, 1304, 1299, 1306, 1303, 1308, 1307, 1305, 1312, 1309, 1314, 1311, 1310, 1316, 1313, 1318, 1317, 1320, 1315, 1322, 1319, 1324, 1323, 1321, 1328, 1325, 1330, 1327, 1326, 1332, 1329, 1334, 1333, 1336, 1331, 1338, 1335, 1340, 1339, 1337, 1344, 1341, 1346, 1343, 1342, 1348, 1345, 1350, 1349, 1352, 1347, 1354, 1351, 1356, 1355, 1353, 1360, 1357, 1362, 1359, 1358, 1364, 1361, 1366, 1365, 1371, 1369, 1370, 1363, 1368, 1367, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535 };
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
        consensus.BIP34Hash = uint256S("0x0019592cd5c0ef222adcaa85d4000602636a05e57b3541a844a90644815cacbb");
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

        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000000000000007ab536");
        consensus.defaultAssumeValid = uint256S("0x00055e4e77d39cc2e0600eebdc773162824fb8d42359879b4916e1adcb0bf4f9");

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

        genesis = CreateGenesisBlock(1723206420, 2847556069, 0x1f7fffff, 1, 11 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        // std::cout << consensus.hashGenesisBlock.ToString() << std::endl;
        // std::cout << genesis.hashMerkleRoot.ToString() << std::endl;
        assert(consensus.hashGenesisBlock == uint256S("0x0019592cd5c0ef222adcaa85d4000602636a05e57b3541a844a90644815cacbb"));
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
                { 0, uint256S("0x0019592cd5c0ef222adcaa85d4000602636a05e57b3541a844a90644815cacbb") },
                { 2180, uint256S("0x00055e4e77d39cc2e0600eebdc773162824fb8d42359879b4916e1adcb0bf4f9") }
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
