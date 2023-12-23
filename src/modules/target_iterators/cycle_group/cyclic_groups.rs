


pub struct CyclicGroup {

    pub prime:u128,                  // 模数
    // known_prim_root:u128,           // (Z/pZ)的已知原始根
    pub prime_factors:[u128;7],     // (P-1)的独特素因子
    pub num_prime_factors:usize,    // 因子数量

}

// 我们将从这个列表中选择第一个比我们允许的IP数量更大的循环组。
// 例如，对于整个互联网扫描，这将是循环32
// 注意：此列表应保持按大小（素数）升序排序。
pub const CYCLE_GROUP:[CyclicGroup;77] = [


    CyclicGroup {
        // 2^4 + 1
        prime: 17,
        // known_prim_root: 3,
        prime_factors: [2, 0, 0, 0, 0, 0, 0],
        num_prime_factors: 1,
    },

    CyclicGroup {
        // 2^5 + 5
        prime: 37,
        // known_prim_root: 2,
        prime_factors: [2, 3, 0, 0, 0, 0, 0],
        num_prime_factors: 2,
    },

    CyclicGroup {
        // 2^6 + 3
        prime: 67,
        // known_prim_root: 2,
        prime_factors: [2, 3, 11, 0, 0, 0, 0],
        num_prime_factors: 3,
    },

    CyclicGroup {
        // 2^7 + 3
        prime: 131,
        // known_prim_root: 2,
        prime_factors: [2, 5, 13, 0, 0, 0, 0],
        num_prime_factors: 3,
    },

    CyclicGroup {
        // 2^8 + 1
        prime: 257,
        // known_prim_root: 3,
        prime_factors: [2, 0, 0, 0, 0, 0, 0],
        num_prime_factors: 1,
    },

    CyclicGroup {
        // 2^9 + 9
        prime: 521,
        // known_prim_root: 3,
        prime_factors: [2, 5, 13, 0, 0, 0, 0],
        num_prime_factors: 3,
    },

    CyclicGroup {
        // 2^10 + 7
        prime: 1031,
        // known_prim_root: 14,
        prime_factors: [2, 5, 103, 0, 0, 0, 0],
        num_prime_factors: 3,
    },

    CyclicGroup {
        // 2^11 + 5
        prime: 2053,
        // known_prim_root: 2,
        prime_factors: [2, 3, 19, 0, 0, 0, 0],
        num_prime_factors: 3,
    },

    CyclicGroup {
        // 2^12 + 3
        prime: 4099,
        // known_prim_root: 2,
        prime_factors: [2, 3, 683, 0, 0, 0, 0],
        num_prime_factors: 3,
    },

    CyclicGroup {
        // 2^13 + 17
        prime: 8209,
        // known_prim_root: 7,
        prime_factors: [2, 3, 19, 0, 0, 0, 0],
        num_prime_factors: 3,
    },

    CyclicGroup {
        // 2^14 + 27
        prime: 16411,
        // known_prim_root: 3,
        prime_factors: [2, 3, 5, 547, 0, 0, 0],
        num_prime_factors: 4,
    },

    CyclicGroup {
        // 2^15 + 3
        prime: 32771,
        // known_prim_root: 2,
        prime_factors: [2, 5, 29, 113, 0, 0, 0],
        num_prime_factors: 4,
    },

    CyclicGroup {
        // 2^16 + 1
        prime: 65537,
        // known_prim_root: 3,
        prime_factors: [2, 0, 0, 0, 0, 0, 0],
        num_prime_factors: 1,
    },

    CyclicGroup {
        // 2^17 + 29
        prime: 131101,
        // known_prim_root: 17,
        prime_factors: [2, 3, 5, 19, 23, 0, 0],
        num_prime_factors: 5,
    },

    CyclicGroup {
        // 2^18 + 3
        prime: 262147,
        // known_prim_root: 2,
        prime_factors: [2, 3, 43691, 0, 0, 0, 0],
        num_prime_factors: 3,
    },

    CyclicGroup {
        // 2^19 + 21
        prime: 524309,
        // known_prim_root: 2,
        prime_factors: [2, 23, 41, 139, 0, 0, 0],
        num_prime_factors: 4,
    },

    CyclicGroup {
        // 2^20 + 7
        prime: 1048583,
        // known_prim_root: 5,
        prime_factors: [2, 29, 101, 179, 0, 0, 0],
        num_prime_factors: 4,
    },

    CyclicGroup {
        // 2^21 + 17
        prime: 2097169,
        // known_prim_root: 47,
        prime_factors: [2, 3, 43691, 0, 0, 0, 0],
        num_prime_factors: 3,
    },

    CyclicGroup {
        // 2^22 + 15
        prime: 4194319,
        // known_prim_root: 3,
        prime_factors: [2, 3, 699053, 0, 0, 0, 0],
        num_prime_factors: 3,
    },

    CyclicGroup {
        // 2^23 + 9
        prime: 8388617,
        // known_prim_root: 3,
        prime_factors: [2, 17, 61681, 0, 0, 0, 0],
        num_prime_factors: 3,
    },

    CyclicGroup {
        // 2^24 + 43
        prime: 16777259,
        // known_prim_root: 2,
        prime_factors: [2, 23, 103, 3541, 0, 0, 0],
        num_prime_factors: 4,
    },

    CyclicGroup {
        // 2^25 + 35
        prime: 33554467,
        // known_prim_root: 2,
        prime_factors: [2, 3, 11, 56489, 0, 0, 0],
        num_prime_factors: 4,
    },

    CyclicGroup {
        // 2^26 + 15
        prime: 67108879,
        // known_prim_root: 3,
        prime_factors: [2, 3, 1242757, 0, 0, 0, 0],
        num_prime_factors: 3,
    },

    CyclicGroup {
        // 2^27 + 29
        prime: 134217757,
        // known_prim_root: 5,
        prime_factors: [2, 3, 1242757, 0, 0, 0, 0],
        num_prime_factors: 3,
    },

    CyclicGroup {
        // 2^28 + 3
        prime: 268435459,
        // known_prim_root: 2,
        prime_factors: [2, 3, 19, 87211, 0, 0, 0],
        num_prime_factors: 4,
    },

    CyclicGroup {
        // 2^29 + 11
        prime: 536870923,
        // known_prim_root: 3,
        prime_factors: [2, 3, 7, 23, 555767, 0, 0],
        num_prime_factors: 5,
    },

    CyclicGroup {
        // 2^30 + 3
        prime: 1073741827,
        // known_prim_root: 2,
        prime_factors: [2, 3, 59, 3033169, 0, 0, 0],
        num_prime_factors: 4,
    },

    CyclicGroup {
        // 2^31 + 11
        prime: 2147483659,
        // known_prim_root: 2,
        prime_factors: [2, 3, 149, 2402107, 0, 0, 0],
        num_prime_factors: 4,
    },

    CyclicGroup {
        // 2^32 + 15
        prime: 4294967311,
        // known_prim_root: 3,
        prime_factors: [2, 3, 5, 131, 364289, 0, 0],
        num_prime_factors: 5,
    },

    CyclicGroup {
        // 2^33 + 17
        prime: 8589934609,
        // known_prim_root: 19,
        prime_factors: [2, 3, 59, 3033169, 0, 0, 0],
        num_prime_factors: 4,
    },

    CyclicGroup {
        // 2^34 + 25
        prime: 17179869209,
        // known_prim_root: 3,
        prime_factors: [2, 83, 1277, 20261, 0, 0, 0],
        num_prime_factors: 4,
    },

    CyclicGroup {
        // 2^35 + 53
        prime: 34359738421,
        // known_prim_root: 2,
        prime_factors: [2, 3, 5, 7, 81808901, 0, 0],
        num_prime_factors: 5,
    },

    CyclicGroup {
        // 2^36 + 31
        prime: 68719476767,
        // known_prim_root: 5,
        prime_factors: [2, 163, 883, 238727, 0, 0, 0],
        num_prime_factors: 4,
    },

    CyclicGroup {
        // 2^37 + 9
        prime: 137438953481,
        // known_prim_root: 3,
        prime_factors: [2, 5, 137, 953, 26317, 0, 0],
        num_prime_factors: 5,
    },

    CyclicGroup {
        // 2^38 + 7
        prime: 274877906951,
        // known_prim_root: 7,
        prime_factors: [2, 5, 35573, 154543, 0, 0, 0],
        num_prime_factors: 4,
    },

    CyclicGroup {
        // 2^39 + 23
        prime: 549755813911,
        // known_prim_root: 3,
        prime_factors: [2, 3, 5, 383, 47846459, 0, 0],
        num_prime_factors: 5,
    },

    CyclicGroup {
        // 2^40 + 15
        prime: 1099511627791,
        // known_prim_root: 3,
        prime_factors: [2, 3, 5, 36650387593, 0, 0, 0],
        num_prime_factors: 4,
    },

    CyclicGroup {
        // 2^41 + 27
        prime: 2199023255579,
        // known_prim_root: 2,
        prime_factors: [2, 277, 3969356057, 0, 0, 0, 0],
        num_prime_factors: 3,
    },

    CyclicGroup {
        // 2^42 + 15
        prime: 4398046511119,
        // known_prim_root: 7,
        prime_factors: [2, 3, 13, 71, 227, 3498493, 0],
        num_prime_factors: 6,
    },

    CyclicGroup {
        // 2^43 + 29
        prime: 8796093022237,
        // known_prim_root: 5,
        prime_factors: [2, 3, 13, 71, 227, 3498493, 0],
        num_prime_factors: 6,
    },

    CyclicGroup {
        // 2^44 + 7
        prime: 17592186044423,
        // known_prim_root: 5,
        prime_factors: [2, 11, 53, 97, 155542661, 0, 0],
        num_prime_factors: 5,
    },

    CyclicGroup {
        // 2^45 + 59
        prime: 35184372088891,
        // known_prim_root: 3,
        prime_factors: [2, 3, 5, 19, 120739, 511243, 0],
        num_prime_factors: 6,
    },

    CyclicGroup {
        // 2^46 + 15
        prime: 70368744177679,
        // known_prim_root: 3,
        prime_factors: [2, 3, 1947973, 6020681, 0, 0, 0],
        num_prime_factors: 4,
    },

    CyclicGroup {
        // 2^47 + 5
        prime: 140737488355333,
        // known_prim_root: 6,
        prime_factors: [2, 3, 11, 19, 331, 18837001, 0],
        num_prime_factors: 6,
    },

    CyclicGroup {
        // 2^48 + 21
        prime: 281474976710677,
        // known_prim_root: 6,
        prime_factors: [2, 3, 7, 1361, 2462081249, 0, 0],
        num_prime_factors: 5,
    },

    CyclicGroup {
        // 2^49 + 69
        prime: 562949953421381,
        // known_prim_root: 2,
        prime_factors: [2, 5, 7, 574438727981, 0, 0, 0],
        num_prime_factors: 4,
    },

    CyclicGroup {
        // 2^50 + 55
        prime: 1125899906842679,
        // known_prim_root: 11,
        prime_factors: [2, 11, 51177268492849, 0, 0, 0, 0],
        num_prime_factors: 3,
    },

    CyclicGroup {
        // 2^51 + 21
        prime: 2251799813685269,
        // known_prim_root: 2,
        prime_factors: [2, 7, 11, 179, 3517, 11613247, 0],
        num_prime_factors: 6,
    },

    CyclicGroup {
        // 2^52 + 21
        prime: 4503599627370517,
        // known_prim_root: 2,
        prime_factors: [2, 3, 23, 612229, 987127, 0, 0],
        num_prime_factors: 5,
    },

    CyclicGroup {
        // 2^53 + 5
        prime: 9007199254740997,
        // known_prim_root: 11,
        prime_factors: [2, 3, 307, 2857, 6529, 43691, 0],
        num_prime_factors: 6,
    },

    CyclicGroup {
        // 2^54 + 159
        prime: 18014398509482143,
        // known_prim_root: 3,
        prime_factors: [2, 3, 7724869, 388666753, 0, 0, 0],
        num_prime_factors: 4,
    },

    CyclicGroup {
        // 2^55 + 3
        prime: 36028797018963971,
        // known_prim_root: 2,
        prime_factors: [2, 5, 13, 37, 109, 246241, 279073],
        num_prime_factors: 7,
    },

    CyclicGroup {
        // 2^56 + 81
        prime: 72057594037928017,
        // known_prim_root: 10,
        prime_factors: [2, 3, 7, 61, 34501, 14557303, 0],
        num_prime_factors: 6,
    },

    CyclicGroup {
        // 2^57 + 9
        prime: 144115188075855881,
        // known_prim_root: 7,
        prime_factors: [2, 5, 13, 37, 109, 246241, 279073],
        num_prime_factors: 7,
    },

    CyclicGroup {
        // 2^58 + 69
        prime: 288230376151711813,
        // known_prim_root: 5,
        prime_factors: [2, 3, 7, 13, 26813, 33829, 290993],
        num_prime_factors: 7,
    },

    CyclicGroup {
        // 2^59 + 131
        prime: 576460752303423619,
        // known_prim_root: 2,
        prime_factors: [2, 3, 1361, 2614547910049, 0, 0, 0],
        num_prime_factors: 4,
    },

    CyclicGroup {
        // 2^60 + 33
        prime: 1152921504606847009,
        // known_prim_root: 13,
        prime_factors: [2, 3, 11, 683, 2971, 48912491, 0],
        num_prime_factors: 6,
    },

    CyclicGroup {
        // 2^61 + 15
        prime: 2305843009213693967,
        // known_prim_root: 5,
        prime_factors: [2, 1723, 2447, 273451615243, 0, 0, 0],
        num_prime_factors: 4,
    },

    CyclicGroup {
        // 2^62 + 135
        prime: 4611686018427388039,
        // known_prim_root: 3,
        prime_factors: [2, 3, 953, 7691, 15467, 6779953, 0],
        num_prime_factors: 6,
    },

    CyclicGroup {
        // 2^63 + 29
        prime: 9223372036854775837,
        // known_prim_root: 5,
        prime_factors: [2, 3, 359, 7005787, 33955849, 0, 0],
        num_prime_factors: 5,
    },

    CyclicGroup {
        // 2^64 + 13
        prime: 18446744073709551629,
        // known_prim_root: 2,
        prime_factors: [2, 7, 658812288346769701, 0, 0, 0, 0],
        num_prime_factors: 3,
    },

    CyclicGroup {
        // 2^65 + 131
        prime: 36893488147419103363,
        // known_prim_root: 2,
        prime_factors: [2, 3, 891329, 1499567, 1533463, 0, 0],
        num_prime_factors: 5,
    },

    CyclicGroup {
        // 2^66 + 9
        prime: 73786976294838206473,
        // known_prim_root: 7,
        prime_factors: [2, 3, 19, 43, 5419, 77158673929, 0],
        num_prime_factors: 6,
    },

    CyclicGroup {
        // 2^67 + 3
        prime: 147573952589676412931,
        // known_prim_root: 2,
        prime_factors: [2, 5, 13, 397, 2113, 312709, 4327489],
        num_prime_factors: 7,
    },

    CyclicGroup {
        // 2^68 + 33
        prime: 295147905179352825889,
        // known_prim_root: 29,
        prime_factors: [2, 3, 19, 43, 5419, 77158673929, 0],
        num_prime_factors: 6,
    },

    CyclicGroup {
        // 2^69 + 29
        prime: 590295810358705651741,
        // known_prim_root: 10,
        prime_factors: [2, 3, 5, 293, 11192563715561351, 0, 0],
        num_prime_factors: 5,
    },

    CyclicGroup {
        // 2^70 + 25
        prime: 1180591620717411303449,
        // known_prim_root: 3,
        prime_factors: [2, 147573952589676412931, 0, 0, 0, 0, 0],
        num_prime_factors: 2,
    },

    CyclicGroup {
        // 2^71 + 11
        prime: 2361183241434822606859,
        // known_prim_root: 3,
        prime_factors: [2, 3, 7, 2789, 4787, 4210837287343, 0],
        num_prime_factors: 6,
    },

    CyclicGroup {
        // 2^72 + 15
        prime: 4722366482869645213711,
        // known_prim_root: 6,
        prime_factors: [2, 3, 5, 4799, 60594931, 541316653, 0],
        num_prime_factors: 6,
    },

    CyclicGroup {
        // 2^73 + 29
        prime: 9444732965739290427421,
        // known_prim_root: 6,
        prime_factors: [2, 3, 5, 4799, 60594931, 541316653, 0],
        num_prime_factors: 6,
    },

    CyclicGroup {
        // 2^74 + 37
        prime: 18889465931478580854821,
        // known_prim_root: 2,
        prime_factors: [2, 5, 17761, 1559689, 34094494829, 0, 0],
        num_prime_factors: 5,
    },

    CyclicGroup {
        // 2^75 + 33
        prime: 37778931862957161709601,
        // known_prim_root: 3,
        prime_factors: [2, 5, 29, 41, 113, 7416361, 47392381],
        num_prime_factors: 7,
    },

    CyclicGroup {
        // 2^76 + 15
        prime: 75557863725914323419151,
        // known_prim_root: 3,
        prime_factors: [2, 3, 5, 971, 518763225032024191, 0, 0],
        num_prime_factors: 5,
    },

    CyclicGroup {
        // 2^77 + 11
        prime: 151115727451828646838283,

        // known_prim_root: 3,
        prime_factors: [2, 3, 7, 8284709, 10362841, 41908709, 0],
        num_prime_factors: 6,
    },

    CyclicGroup {
        // 2^78 + 7
        prime: 302231454903657293676551,
        // known_prim_root: 13,
        prime_factors: [2, 5, 7, 389, 2219841754709197897, 0, 0],
        num_prime_factors: 5,
    },

    CyclicGroup {
        // 2^79 + 23
        prime: 604462909807314587353111,
        // known_prim_root: 7,
        prime_factors: [2, 3, 5, 419, 3677, 13077982440185699, 0],
        num_prime_factors: 6,
    },

    CyclicGroup {
        // 2^80 + 13
        prime: 1208925819614629174706189,
        // known_prim_root: 2,
        prime_factors: [2, 1093, 31039, 8908647580887961, 0, 0, 0],
        num_prime_factors: 4,
    },

];