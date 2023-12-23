
use rand::rngs::StdRng;
use crate::core::conf::tools::args_parse::target_iterator::TarIterBaseConf;
use crate::modules::target_iterators::cycle_group::cyclic::Cyclic;


pub struct CyclicPort {

    pub p:u128,
    pub prim_root:u128,
    pub p_sub_one:u128,


    pub bits_for_port:u32,
    pub bits_num:u32,

}


impl CyclicPort {

    pub fn new(tar_ip_num:u64, tar_port_num:usize, rng:&mut StdRng, type_max:u128) -> Self {

        // 计算 ip 和 port 所需要的位数
        let bits_for_ip = TarIterBaseConf::bits_needed_u64(tar_ip_num);
        let bits_for_port = TarIterBaseConf::bits_needed_usize(tar_port_num);

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
            prim_root:Cyclic::get_prim_root(&group, rng, Cyclic::get_max_root(p_sub_one, type_max)),
            p_sub_one,

            bits_for_port,
            bits_num,
        }
    }


}