use rand::rngs::StdRng;
use crate::modules::target_iterators::cycle_group::cyclic::Cyclic;
use crate::modules::target_iterators::cycle_group::cycle_group_with_port::cyclic_with_port::CyclicPort;



impl Cyclic {

    pub fn new_from_pattern(bits_for_ip:u32, rng:&mut StdRng, type_max:u128) -> Self {

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
}

impl CyclicPort {

    pub fn new_from_pattern(bits_for_ip:u32, bits_for_port:u32, rng:&mut StdRng, type_max:u128) -> Self {

        // 计算 乘法群模数的最小值
        // 最小值为  [ 0 .. 1 | ip 位数 | 端口 位数 ]
        let bits_num = bits_for_ip + bits_for_port;
        let group_min_size = 1u128 << bits_num;

        // 获得大于 最小元素 的 质数乘法群
        let group = Cyclic::get_group(group_min_size);

        // 计算 p - 1
        let p_sub_one = group.prime - 1;

        Self {
            p:group.prime,
            prim_root: Cyclic::get_prim_root(&group, rng, Cyclic::get_max_root(p_sub_one, type_max)),
            p_sub_one,
            bits_for_port,
            bits_num,
        }
    }
}