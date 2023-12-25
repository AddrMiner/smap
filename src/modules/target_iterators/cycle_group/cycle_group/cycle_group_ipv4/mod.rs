mod get_targets;



use std::process::exit;
use log::error;
use rand::rngs::StdRng;
use crate::modules::target_iterators::cycle_group::cyclic::Cyclic;
use crate::SYS;

/// ipv4 乘法循环群
#[derive(Clone)]
pub struct CycleIpv4 {

    p:u64,
    prim_root:u64,
    pub p_sub_one:u64,

    // 经过乘法群计算, 应用于探测的 当前目标 和 最后一个目标值
    pub current:u64,
    pub last:u64,

    // 目标值有效范围
    valid_range:u64,

    // 起始地址
    start_ip:u32,
}



impl CycleIpv4 {

    pub fn new(start_ip:u32, tar_ip_num:u64, rng:&mut StdRng) -> Self {

        // 获得 乘法循环群
        let cycle = Cyclic::new(tar_ip_num, rng, u64::MAX as u128);

        Self {
            p: Cyclic::get_val_with_check_u64(cycle.p),
            prim_root: Cyclic::get_val_with_check_u64(cycle.prim_root),
            p_sub_one: Cyclic::get_val_with_check_u64(cycle.p_sub_one),

            // 这里只做初始化, 没有实际意义
            current: 0,
            last: 0,


            valid_range: tar_ip_num + 1,
            start_ip,
        }
    }


    /// 从<u>整体循环群</u>为每个发送线程创建<u>扫描范围</u>   index:[1..p-1]
    /// 这里的 start_index, end_index 为指数顺序范围, 比如 2->4 就是 3^2≡2(mod 7)，3^3≡6(mod 7)，3^4≡4(mod 7)
    pub fn init(&self, start_index:u64, end_index:u64) -> Self {

        // start_index 和 end_index 均为 [1, p-1], 且 start_index 必须小于等于 end_index
        if start_index > end_index || start_index < 1 || end_index > self.p_sub_one {
            error!("{}", SYS.get_info("err", "index_invalid"));
            exit(1)
        }

        // 转换成对应大数
        let big_p = Cyclic::parse_u64_to_big_num(self.p);
        let big_prim_root = Cyclic::parse_u64_to_big_num(self.prim_root);
        let big_start = Cyclic::parse_u64_to_big_num(start_index);
        let big_end  = Cyclic::parse_u64_to_big_num(end_index);

        // 计算 根据当前乘法群遍历到的 第一个目标(索引) 和 最后一个目标  prim_root^(start) % p
        let big_first = big_prim_root.modpow(&big_start, &big_p);
        let big_last  = big_prim_root.modpow(&big_end, &big_p);

        Self {
            p: self.p,
            prim_root: self.prim_root,
            p_sub_one: self.p_sub_one,

            current:Cyclic::parse_big_num_to_u64(big_first),
            last:Cyclic::parse_big_num_to_u64(big_last),

            valid_range: self.valid_range,
            start_ip: self.start_ip,
        }

    }


    /// 初始化全部扫描范围
    #[allow(dead_code)]
    pub fn init_whole(&self) -> Self {
        self.init(1, self.p_sub_one)
    }
}


