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
    genesis.vdfSolution = { 1379, 1383, 1372, 1377, 1380, 1385, 1388, 1382, 1381, 1384, 1386, 1387, 1391, 1390, 1389, 1392, 1394, 1395, 1399, 1398, 1397, 1400, 1402, 1393, 1396, 1401, 1404, 1409, 1407, 1403, 1408, 1405, 1406, 1412, 1417, 1415, 1411, 1410, 1414, 1413, 1416, 1418, 1419, 1423, 1422, 1421, 1424, 1426, 1427, 1431, 1420, 1425, 1428, 1433, 1436, 1430, 1429, 1432, 1434, 1435, 1439, 1438, 1437, 1440, 1442, 1443, 1447, 1446, 1445, 1448, 1450, 1441, 1444, 1449, 1452, 1457, 1455, 1451, 1456, 1453, 1454, 1460, 1465, 1463, 1459, 1458, 1462, 1461, 1464, 1466, 1467, 1471, 1470, 1469, 1472, 1474, 1475, 1479, 1468, 1473, 1476, 1481, 1484, 1478, 1477, 1480, 1482, 1483, 1487, 1486, 1485, 1488, 1490, 1491, 1495, 1494, 1493, 1496, 1498, 1489, 1492, 1497, 1500, 1505, 1503, 1499, 1504, 1501, 1502, 1508, 1513, 1511, 1507, 1506, 1510, 1509, 1512, 1514, 1515, 1519, 1518, 1517, 1520, 1522, 1523, 1527, 1516, 1521, 1524, 1529, 1532, 1526, 1525, 1528, 1530, 1531, 1535, 1534, 1533, 1536, 1538, 1539, 1543, 1542, 1541, 1544, 1546, 1537, 1540, 1545, 1548, 1553, 1551, 1547, 1552, 1549, 1550, 1556, 1561, 1559, 1555, 1554, 1558, 1557, 1560, 1562, 1563, 1567, 1566, 1565, 1568, 1570, 1571, 1575, 1564, 1569, 1572, 1577, 1580, 1574, 1573, 1576, 1578, 1579, 1583, 1585, 1588, 1582, 1581, 1584, 1586, 1587, 1591, 1590, 1589, 1592, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 0, 2, 3, 7, 6, 5, 8, 10, 1, 4, 9, 12, 17, 15, 11, 16, 13, 14, 20, 25, 23, 19, 18, 22, 21, 24, 26, 27, 31, 30, 29, 32, 34, 35, 39, 28, 33, 36, 41, 44, 38, 37, 40, 42, 43, 47, 46, 45, 48, 50, 51, 55, 54, 53, 56, 58, 49, 52, 57, 60, 65, 63, 59, 64, 61, 62, 68, 73, 71, 67, 66, 70, 69, 72, 74, 75, 79, 78, 77, 80, 82, 83, 87, 76, 81, 84, 89, 92, 86, 85, 88, 90, 91, 95, 94, 93, 96, 98, 99, 103, 102, 101, 104, 106, 97, 100, 105, 108, 113, 111, 107, 112, 109, 110, 116, 121, 119, 115, 114, 118, 117, 120, 122, 123, 127, 126, 125, 128, 130, 131, 135, 124, 129, 132, 137, 140, 134, 133, 136, 138, 139, 143, 142, 141, 144, 146, 147, 151, 150, 149, 152, 154, 145, 148, 153, 156, 161, 159, 155, 160, 157, 158, 164, 169, 167, 163, 162, 166, 165, 168, 170, 171, 175, 174, 173, 176, 178, 179, 183, 172, 177, 180, 185, 188, 182, 181, 184, 186, 187, 191, 190, 189, 192, 194, 195, 199, 198, 197, 200, 202, 193, 196, 201, 204, 209, 207, 203, 208, 205, 206, 212, 217, 215, 211, 210, 214, 213, 216, 218, 219, 223, 222, 221, 224, 226, 227, 231, 220, 225, 228, 233, 236, 230, 229, 232, 234, 235, 239, 238, 237, 240, 242, 243, 247, 246, 245, 248, 250, 241, 244, 249, 252, 257, 255, 251, 256, 253, 254, 260, 265, 263, 259, 258, 262, 261, 264, 266, 267, 271, 270, 269, 272, 274, 275, 279, 268, 273, 276, 281, 284, 278, 277, 280, 282, 283, 287, 286, 285, 288, 290, 291, 295, 294, 293, 296, 298, 289, 292, 297, 300, 305, 303, 299, 304, 301, 302, 308, 313, 311, 307, 306, 310, 309, 312, 314, 315, 319, 318, 317, 320, 322, 323, 327, 316, 321, 324, 329, 332, 326, 325, 328, 330, 331, 335, 334, 333, 336, 338, 339, 343, 342, 341, 344, 346, 337, 340, 345, 348, 353, 351, 347, 352, 349, 350, 356, 361, 359, 355, 354, 358, 357, 360, 362, 363, 367, 366, 365, 368, 370, 371, 375, 364, 369, 372, 377, 380, 374, 373, 376, 378, 379, 383, 382, 381, 384, 386, 387, 391, 390, 389, 392, 394, 385, 388, 393, 396, 401, 399, 395, 400, 397, 398, 404, 409, 407, 403, 402, 406, 405, 408, 410, 411, 415, 414, 413, 416, 418, 419, 423, 412, 417, 420, 425, 428, 422, 421, 424, 426, 427, 431, 430, 429, 432, 434, 435, 439, 438, 437, 440, 442, 433, 436, 441, 444, 449, 447, 443, 448, 445, 446, 452, 457, 455, 451, 450, 454, 453, 456, 458, 459, 463, 462, 461, 464, 466, 467, 471, 460, 465, 468, 473, 476, 470, 469, 472, 474, 475, 479, 478, 477, 480, 482, 483, 487, 486, 485, 488, 490, 481, 484, 489, 492, 497, 495, 491, 496, 493, 494, 500, 505, 503, 499, 498, 502, 501, 504, 506, 507, 511, 510, 509, 512, 514, 515, 519, 508, 513, 516, 521, 524, 518, 517, 520, 522, 523, 527, 526, 525, 528, 530, 531, 535, 534, 533, 536, 538, 529, 532, 537, 540, 545, 543, 539, 544, 541, 542, 548, 553, 551, 547, 546, 550, 549, 552, 554, 555, 559, 558, 557, 560, 562, 563, 567, 556, 561, 564, 569, 572, 566, 565, 568, 570, 571, 575, 574, 573, 576, 578, 579, 583, 582, 581, 584, 586, 577, 580, 585, 588, 593, 591, 587, 592, 589, 590, 596, 601, 599, 595, 594, 598, 597, 600, 602, 603, 607, 606, 605, 608, 610, 611, 615, 604, 609, 612, 617, 620, 614, 613, 616, 618, 619, 623, 622, 621, 624, 626, 627, 631, 630, 629, 632, 634, 625, 628, 633, 636, 641, 639, 635, 640, 637, 638, 644, 649, 647, 643, 642, 646, 645, 648, 650, 651, 655, 654, 653, 656, 658, 659, 663, 652, 657, 660, 665, 668, 662, 661, 664, 666, 667, 671, 670, 669, 672, 674, 675, 679, 678, 677, 680, 682, 673, 676, 681, 684, 689, 687, 683, 688, 685, 686, 692, 697, 695, 691, 690, 694, 693, 696, 698, 699, 703, 702, 701, 704, 706, 707, 711, 700, 705, 708, 713, 716, 710, 709, 712, 714, 715, 719, 718, 717, 720, 722, 723, 727, 726, 725, 728, 730, 721, 724, 729, 732, 737, 735, 731, 736, 733, 734, 740, 745, 743, 739, 738, 742, 741, 744, 746, 747, 751, 750, 749, 752, 754, 755, 759, 748, 753, 756, 761, 764, 758, 757, 760, 762, 763, 767, 766, 765, 768, 770, 771, 775, 774, 773, 776, 778, 769, 772, 777, 780, 785, 783, 779, 784, 781, 782, 788, 793, 791, 787, 786, 790, 789, 792, 794, 795, 799, 798, 797, 800, 802, 803, 807, 796, 801, 804, 809, 812, 806, 805, 808, 810, 811, 815, 814, 813, 816, 818, 819, 823, 822, 821, 824, 826, 817, 820, 825, 828, 833, 831, 827, 832, 829, 830, 836, 841, 839, 835, 834, 838, 837, 840, 842, 843, 847, 846, 845, 848, 850, 851, 855, 844, 849, 852, 857, 860, 854, 853, 856, 858, 859, 863, 862, 861, 864, 866, 867, 871, 870, 869, 872, 874, 865, 868, 873, 876, 881, 879, 875, 880, 877, 878, 884, 889, 887, 883, 882, 886, 885, 888, 890, 891, 895, 894, 893, 896, 898, 899, 903, 892, 897, 900, 905, 908, 902, 901, 904, 906, 907, 911, 910, 909, 912, 914, 915, 919, 918, 917, 920, 922, 913, 916, 921, 924, 929, 927, 923, 928, 925, 926, 932, 937, 935, 931, 930, 934, 933, 936, 938, 939, 943, 942, 941, 944, 946, 947, 951, 940, 945, 948, 953, 956, 950, 949, 952, 954, 955, 959, 958, 957, 960, 962, 963, 967, 966, 965, 968, 970, 961, 964, 969, 972, 977, 975, 971, 976, 973, 974, 980, 985, 983, 979, 978, 982, 981, 984, 986, 987, 991, 990, 989, 992, 994, 995, 999, 988, 993, 996, 1001, 1004, 998, 997, 1000, 1002, 1003, 1007, 1006, 1005, 1008, 1010, 1011, 1015, 1014, 1013, 1016, 1018, 1009, 1012, 1017, 1020, 1025, 1023, 1019, 1024, 1021, 1022, 1028, 1033, 1031, 1027, 1026, 1030, 1029, 1032, 1034, 1035, 1039, 1038, 1037, 1040, 1042, 1043, 1047, 1036, 1041, 1044, 1049, 1052, 1046, 1045, 1048, 1050, 1051, 1055, 1054, 1053, 1056, 1058, 1059, 1063, 1062, 1061, 1064, 1066, 1057, 1060, 1065, 1068, 1073, 1071, 1067, 1072, 1069, 1070, 1076, 1081, 1079, 1075, 1074, 1078, 1077, 1080, 1082, 1083, 1087, 1086, 1085, 1088, 1090, 1091, 1095, 1084, 1089, 1092, 1097, 1100, 1094, 1093, 1096, 1098, 1099, 1103, 1102, 1101, 1104, 1106, 1107, 1111, 1110, 1109, 1112, 1114, 1105, 1108, 1113, 1116, 1121, 1119, 1115, 1120, 1117, 1118, 1124, 1129, 1127, 1123, 1122, 1126, 1125, 1128, 1130, 1131, 1135, 1134, 1133, 1136, 1138, 1139, 1143, 1132, 1137, 1140, 1145, 1148, 1142, 1141, 1144, 1146, 1147, 1151, 1150, 1149, 1152, 1154, 1155, 1159, 1158, 1157, 1160, 1162, 1153, 1156, 1161, 1164, 1169, 1167, 1163, 1168, 1165, 1166, 1172, 1177, 1175, 1171, 1170, 1174, 1173, 1176, 1178, 1179, 1183, 1182, 1181, 1184, 1186, 1187, 1191, 1180, 1185, 1188, 1193, 1196, 1190, 1189, 1192, 1194, 1195, 1199, 1198, 1197, 1200, 1202, 1203, 1207, 1206, 1205, 1208, 1210, 1201, 1204, 1209, 1212, 1217, 1215, 1211, 1216, 1213, 1214, 1220, 1225, 1223, 1219, 1218, 1222, 1221, 1224, 1226, 1227, 1231, 1230, 1229, 1232, 1234, 1235, 1239, 1228, 1233, 1236, 1241, 1244, 1238, 1237, 1240, 1242, 1243, 1247, 1246, 1245, 1248, 1250, 1251, 1255, 1254, 1253, 1256, 1258, 1249, 1252, 1257, 1260, 1265, 1263, 1259, 1264, 1261, 1262, 1268, 1273, 1271, 1267, 1266, 1270, 1269, 1272, 1274, 1275, 1279, 1278, 1277, 1280, 1282, 1283, 1287, 1276, 1281, 1284, 1289, 1292, 1286, 1285, 1288, 1290, 1291, 1295, 1294, 1293, 1296, 1298, 1299, 1303, 1302, 1301, 1304, 1306, 1297, 1300, 1305, 1308, 1313, 1311, 1307, 1312, 1309, 1310, 1316, 1321, 1319, 1315, 1314, 1318, 1317, 1320, 1322, 1323, 1327, 1326, 1325, 1328, 1330, 1331, 1335, 1324, 1329, 1332, 1337, 1340, 1334, 1333, 1336, 1338, 1339, 1343, 1342, 1341, 1344, 1346, 1347, 1351, 1350, 1349, 1352, 1354, 1345, 1348, 1353, 1356, 1361, 1359, 1355, 1360, 1357, 1358, 1364, 1369, 1367, 1363, 1362, 1366, 1365, 1368, 1370, 1371, 1375, 1374, 1373, 1376, 1378 };
    genesis.hashRandomX = uint256S("0x8e9c1666c7a500bf10e5e18167eb4de6212bca7b920ef132c3a63a098d9a8d26");

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
        consensus.tailEmissionBlockHeight = 420480;
        consensus.script_flag_exceptions.emplace( // BIP16 exception
            uint256S("0x00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"), SCRIPT_VERIFY_NONE);
        consensus.script_flag_exceptions.emplace( // Taproot exception
            uint256S("0x0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"), SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS);
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x0000e840cf327fca83b072da0cedfa33d538b625cbe0e39a109a331faace15b5");
        consensus.BIP65Height = 1; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP66Height = 1; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.CSVHeight = 1; // 000000000000000004a1b34462cb8aeebd5799177f7a29cf28f2d1961716b5b5
        consensus.SegwitHeight = 1; // 0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893
        consensus.MinBIP9WarningHeight = 2016; // segwit activation height + miner confirmation window
        consensus.powLimit = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 2 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016
        consensus.nMinerConfirmationWindow = 24; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = 1619222400; // April 24th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = 1628640000; // August 11th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 1; // Approximately November 12th, 2021

        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000000009e5f91d1");
        consensus.defaultAssumeValid = uint256S("0x000001bdc3b5cbaa4c276f02bdb782061a6bea3e25ded88d574e5728cb0ae16d"); // 555

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xe4;
        pchMessageStart[1] = 0x3a;
        pchMessageStart[2] = 0x7c;
        pchMessageStart[3] = 0xd1;
        nDefaultPort = 42069;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 600;
        m_assumed_chain_state_size = 10;

        genesis = CreateGenesisBlock(1718772321, 3250375205, 0x1f00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0000e840cf327fca83b072da0cedfa33d538b625cbe0e39a109a331faace15b5"));
        assert(genesis.hashMerkleRoot == uint256S("0x5b53a050a9980529aacc59a2e30e15f7540b6021d06da511d87e3e3d0e4f7644"));

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
                { 555, uint256S("0x000001bdc3b5cbaa4c276f02bdb782061a6bea3e25ded88d574e5728cb0ae16d")},
            }
        };

        m_assumeutxo_data = {
            // TODO to be specified in a future patch.
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 555 000000000000000000026811d149d4d261995ec5b3f64f439a0a10e1a464af9a
            .nTime    = 1719590520,
            .nTxCount = 556,
            .dTxRate  = 0.004139054293334927,
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
        consensus.tailEmissionBlockHeight = 210000;
        consensus.script_flag_exceptions.emplace( // BIP16 exception
            uint256S("0x00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"), SCRIPT_VERIFY_NONE);
        consensus.BIP34Height = 21111;
        consensus.BIP34Hash = uint256S("0x0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
        consensus.BIP65Height = 581885; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP66Height = 330776; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.CSVHeight = 770112; // 00000000025e930139bac5c6c31a403776da130831ab85be56578f3fa75369bb
        consensus.SegwitHeight = 834624; // 00000000002b980fcd729daaa248fd9316a5200e9b367f4ff2c42453e84201ca
        consensus.MinBIP9WarningHeight = 836640; // segwit activation height + miner confirmation window
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = 1619222400; // April 24th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = 1628640000; // August 11th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000c59b14e264ba6c15db9");
        consensus.defaultAssumeValid = uint256S("0x000000000001323071f38f21ea5aae529ece491eadaccce506a59bcc2d968917"); // 2550000

        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x09;
        pchMessageStart[3] = 0x07;
        nDefaultPort = 18333;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 42;
        m_assumed_chain_state_size = 3;

        genesis = CreateGenesisBlock(1296688602, 414098458, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        // assert(consensus.hashGenesisBlock == uint256S("0x000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"));
        // assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("testnet-seed.bitcoin.jonasschnelli.ch.");
        vSeeds.emplace_back("seed.tbtc.petertodd.net.");
        vSeeds.emplace_back("seed.testnet.bitcoin.sprovoost.nl.");
        vSeeds.emplace_back("testnet-seed.bluematt.me."); // Just a static list of stable node(s), only supports x9

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
                {546, uint256S("000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70")},
            }
        };

        m_assumeutxo_data = {
            {
                .height = 2'500'000,
                .hash_serialized = AssumeutxoHash{uint256S("0xf841584909f68e47897952345234e37fcd9128cd818f41ee6c3ca68db8071be7")},
                .nChainTx = 66484552,
                .blockhash = uint256S("0x0000000000000093bcb68c03a9a168ae252572d348a2eaeba2cdf9231d73206f")
            }
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
