
mod get_targets;

use std::process::exit;
use log::error;
use rand::rngs::StdRng;
use crate::modules::target_iterators::cycle_group::cycle_group_with_port::cyclic_with_port::CyclicPort;
use crate::modules::target_iterators::cycle_group::cyclic::Cyclic;
use crate::SYS;

/// ipv4 乘法循环群
#[derive(Clone)]
pub struct CycleIpv4Port {

    p:u64,
    prim_root:u64,
    pub p_sub_one:u64,

    // 经过乘法群计算, 应用于探测的 当前目标 和 最后一个目标值
    current:u64,
    last:u64,

    // ip(省略) 和 port 分别占的位数,   [ 0..0 | ip | port ]
    bits_for_port:u32,

    // 取得port时的移动位数, 加速计算
    port_move_len:u32,

    // 根据 ip 和 port 计算得到的 目标值有效范围
    valid_range:u64,

    // 保存目标端口总数, 用于 筛选乘法群 生成的无效值
    tar_port_num:usize,

    // 起始地址
    start_ip:u32,

    // 目的端口数组
    pub tar_ports:Vec<u16>,

}


impl CycleIpv4Port {

    /// 以<u>整体探测范围</u>创建乘法群, 适用于 ipv4
    pub fn new(start_ip:u32,tar_ip_num:u64,
               tar_ports:Vec<u16>, rng:&mut StdRng) -> Self {

        // 获得 乘法循环群
        let cycle = CyclicPort::new(tar_ip_num, tar_ports.len(), rng, u64::MAX as u128);

        Self {
            p: Cyclic::get_val_with_check_u64(cycle.p),
            prim_root: Cyclic::get_val_with_check_u64(cycle.prim_root),
            p_sub_one: Cyclic::get_val_with_check_u64(cycle.p_sub_one),

            // 这里只做初始化, 没有实际意义
            current: 0,
            last: 0,

            bits_for_port: cycle.bits_for_port,
            port_move_len: 64 - cycle.bits_for_port,

            // // 使得乘法群生成的值始终在 [1, 2^( ip 和 port 占的总位数)]
            // valid_range: ((1 << cycle.bits_num) + 1),

            // 注意该项必须仔细检查
            valid_range:Self::get_valid_range(tar_ip_num, cycle.bits_for_port),

            tar_port_num:tar_ports.len(),

            start_ip,
            tar_ports,
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

            bits_for_port: self.bits_for_port,
            port_move_len: self.port_move_len,

            valid_range: self.valid_range,

            tar_port_num: self.tar_port_num,

            start_ip: self.start_ip,
            tar_ports: self.tar_ports.clone(),
        }

    }


    /// 初始化全部扫描范围
    #[allow(dead_code)]
    pub fn init_whole(&self) -> Self {
        self.init(1, self.p_sub_one)
    }


    /// 获得乘法循环群输出刚好得不到的值

    pub fn get_valid_range(tar_ip_num:u64, bits_for_port:u32) -> u64 {

        let mut mask:u64 = 0;
        let mut left_bit = bits_for_port;

        while left_bit != 0 {

            mask = mask << 1;
            mask = mask | 1;

            left_bit -= 1;
        }

        // 注意: 检查到这里的时候必须小心验证
        // 乘法群输出的最大值应为        [    0..   |   tar_ip_num - 1  |  1..   ]  + 1
        // 小于号运算下, 限制条件应为    [    0..   |   tar_ip_num - 1  |   1..  ]  + 1 + 1

        let ip_val:u64 = (tar_ip_num - 1) << bits_for_port;
        let ip_val = ip_val | mask;

        ip_val + 2
    }

}


