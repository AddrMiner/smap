mod get_targets;

use crate::SYS;
use std::process::exit;
use log::error;
use rand::prelude::StdRng;
use crate::modules::target_iterators::cycle_group::cyclic::Cyclic;


#[derive(Clone)]
pub struct CycleIpv4Pattern {

    p:u64,
    prim_root:u64,
    pub p_sub_one:u64,

    // 经过乘法群计算, 应用于探测的 当前目标 和 最后一个目标值
    pub current:u64,
    pub last:u64,


    // 基础ip值   把模式字符串中的 模式字符 置换为0后的 ip值
    base_ip_val:u32,
    // ip 片段的位移量
    // (0: 第一次左移位数, 1: 右移位数, 2: 第二次左移位数)
    pub ip_move_len:Vec<(u32,u32,u32)>,


    // 根据 ip 占的比特位数计算得到的 目标值有效范围
    valid_range:u64,
}


impl CycleIpv4Pattern {

    pub fn new(bits_for_ip:u32, base_ip_val:u32, parts:Vec<(u32, u32)>, rng:&mut StdRng) -> Self {

        // 获取片段移动位数, 注意: 这里端口位数为 0
        let ip_move_len = Cyclic::get_move_len(bits_for_ip, 0, parts, 32);

        // 获得乘法循环群
        let cycle = Cyclic::new_from_pattern(bits_for_ip, rng, u64::MAX as u128);

        Self {
            p: Cyclic::get_val_with_check_u64(cycle.p),
            prim_root: Cyclic::get_val_with_check_u64(cycle.prim_root),
            p_sub_one: Cyclic::get_val_with_check_u64(cycle.p_sub_one),

            // 这里只做初始化, 没有实际意义
            current: 0,
            last: 0,

            base_ip_val,
            ip_move_len,

            // 使得乘法群生成的值始终在 [1, 2^( ip 和 port 占的总位数)]
            valid_range: (1 << cycle.bits_num) + 1,
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

            base_ip_val: self.base_ip_val,
            ip_move_len: self.ip_move_len.clone(),

            valid_range: self.valid_range,
        }
    }

    /// 初始化全部扫描范围
    #[allow(dead_code)]
    pub fn init_whole(&self) -> Self {
        self.init(1, self.p_sub_one)
    }
}
