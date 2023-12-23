use std::cmp::min;
use std::process::exit;
use log::error;
use num_traits::ToPrimitive;
use rand::prelude::StdRng;
use rand::Rng;
use crate::core::conf::tools::args_parse::target_iterator::TarIterBaseConf;
use crate::modules::target_iterators::cycle_group::cyclic_groups::{CYCLE_GROUP, CyclicGroup};
use crate::SYS;

pub struct Cyclic {

    pub p:u128,
    pub prim_root:u128,
    pub p_sub_one:u128,

    pub bits_num:u32,
}

impl Cyclic {

    pub fn new(tar_ip_num:u64, rng:&mut StdRng, type_max:u128) -> Self {

        // 计算 ip 需要的位数
        let bits_for_ip = TarIterBaseConf::bits_needed_u64(tar_ip_num);

        // 计算 乘法群模数的最小值
        // 最小值为  [ 0 .. 1 | ip 位数 ]
        let group_min_size = 1u128 << bits_for_ip;

        // 获得大于 最小元素 的 质数乘法群
        let group = Cyclic::get_group(group_min_size);

        // 计算 p - 1
        let p_sub_one = group.prime - 1;

        Self {
            p: group.prime,
            prim_root: Cyclic::get_prim_root(&group, rng, Cyclic::get_max_root(p_sub_one, type_max)),
            p_sub_one,

            bits_num: bits_for_ip,
        }
    }


    /// 找出和<u>最小元素</u>相匹配的<u>乘法群</u>
    pub fn get_group(min_size:u128) -> CyclicGroup {

        for i in CYCLE_GROUP {

            if i.prime > min_size {
                return i
            }
        }

        error!("{}", SYS.get_info("err", "cycle_group_not_found"));
        exit(1)
    }

    /// 根据选定的乘法群生成原根
    pub fn get_prim_root(group:&CyclicGroup, rng:&mut StdRng, max_root:u128) -> u128 {

        // 生成一个随机数
        let mut candidate:u128 = rng.gen_range(2..group.prime);

        // 获得足够小的 原根
        loop {

            candidate %= max_root;           // c = c % m    确保 候选 比 最大根小

            let prime = Self::parse_u128_to_big_num(group.prime);

            let mut ok = true;
            for i in 0..group.num_prime_factors {       // 循环 因子数量

                let q = group.prime_factors[i];             // 依次取出 对应因子
                let k = (group.prime - 1) / q;              // k = ( p - 1 ) / 因子

                let base = Self::parse_u128_to_big_num(candidate);
                let power = Self::parse_u128_to_big_num(k);

                // 候选 ^ ( ( p - 1 ) / 因子 )  % p
                let res = base.modpow(&power,&prime);

                let res_ui = match res.to_u128() {
                    Some(r) => r,
                    None => {
                        error!("{}", SYS.get_info("err", "get_prim_root_err"));
                        exit(1)
                    }
                };

                // 如果有一个因子的对应值为 1
                if res_ui == 1 {
                    // 说明不是原根, 直接退出循环
                    ok = false;
                    break
                }

            }

            if ok {
                // 如果所有因子的对应值都不是 1, 说明是 原根
                if candidate != 0 {
                    // 注意不能为 0
                    return candidate
                }
            }

            candidate += 1;
            candidate %= group.prime;        // c = c % p
        }

        // https://blog.csdn.net/zhang20072844/article/details/11541133?spm=1001.2101.3001.6650.5&utm_medium=distribute.pc_relevant.none-task-blog-2%7Edefault%7EBlogCommendFromBaidu%7ERate-5-11541133-blog-50498671.235%5Ev38%5Epc_relevant_anti_vip&depth_1-utm_source=distribute.pc_relevant.none-task-blog-2%7Edefault%7EBlogCommendFromBaidu%7ERate-5-11541133-blog-50498671.235%5Ev38%5Epc_relevant_anti_vip&utm_relevant_index=9
    }


    /// 计算最大根
    /// max_root 选定规则    max_root * (p-1) <= 类型所能表示的最大值
    /// 考虑可能面临的计算问题, 再限制为 它 和 1 << 22 中的较小值
    pub fn get_max_root(p_sub_one:u128, type_max:u128) -> u128{
        let max_root = type_max / p_sub_one;
        min(max_root, 1u128 << 22 )
    }
}


