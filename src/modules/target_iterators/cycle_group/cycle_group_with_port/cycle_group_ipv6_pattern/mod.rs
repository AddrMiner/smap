
mod get_targets;

use std::process::exit;
use log::error;
use rand::rngs::StdRng;
use crate::core::conf::tools::args_parse::target_iterator::TarIterBaseConf;
use crate::modules::target_iterators::cycle_group::cycle_group_with_port::cyclic_with_port::CyclicPort;
use crate::modules::target_iterators::cycle_group::cyclic::Cyclic;
use crate::SYS;

/// ipv6 模式字符串 乘法循环群
pub struct CycleIpv6PatternPort {

    p:u128,
    prim_root:u128,
    pub p_sub_one:u128,

    // 经过乘法群计算, 应用于探测的 当前目标 和 最后一个目标值
    current:u128,
    last:u128,

    // 基础ip值   把模式字符串中的 模式字符 置换为0后的 ip值
    base_ip_val:u128,
    // ip 片段的位移量
    // (0: 第一次左移位数, 1: 右移位数, 2: 第二次左移位数)
    ip_move_len:Vec<(u32,u32,u32)>,

    // ip(省略) 和 port 分别占的位数,   [ 0..0 | ip | port ]
    bits_for_port:u32,

    // 取得port时的移动位数, 加速计算
    port_move_len:u32,

    // 根据 ip 和 port 总共占的比特位数计算得到的 目标值有效范围
    valid_range:u128,

    // 保存 目标端口 总数, 用于 筛选乘法群 生成的无效值
    tar_port_num:usize,

    // 目的端口数组
    pub tar_ports:Vec<u16>,

}


impl CycleIpv6PatternPort {

    /// 创建 ipv6模式字符串 乘法循环群
    pub fn new(bits_for_ip:u32, base_ip_val:u128, parts:Vec<(u32, u32)>,
               tar_ports:Vec<u16>, rng:&mut StdRng) -> Self {

        let bits_for_port = TarIterBaseConf::bits_needed_usize(tar_ports.len());

        // 获取片段移动位数
        let ip_move_len = Cyclic::get_move_len(bits_for_ip, bits_for_port, parts, 128);

        // 获得乘法循环群
        let cycle = CyclicPort::new_from_pattern(bits_for_ip, bits_for_port, rng, u128::MAX);

        Self {
            p: cycle.p,
            prim_root: cycle.prim_root,
            p_sub_one: cycle.p_sub_one,

            // 这里只做初始化, 没有实际意义
            current: 0,
            last: 0,

            base_ip_val,
            ip_move_len,

            bits_for_port: cycle.bits_for_port,
            port_move_len: 128 - cycle.bits_for_port,

            // 使得乘法群生成的值始终在 [1, 2^( ip 和 port 占的总位数)]
            valid_range: (1 << cycle.bits_num) + 1,

            tar_port_num:tar_ports.len(),
            tar_ports,
        }
    }

    /// 从<u>整体循环群</u>为每个发送线程创建<u>扫描范围</u>   index:[1..p-1]
    /// 这里的 start_index, end_index 为指数顺序范围, 比如 2->4 就是 3^2≡2(mod 7)，3^3≡6(mod 7)，3^4≡4(mod 7)
    pub fn init(&self, start_index:u128, end_index:u128) -> Self {

        // start_index 和 end_index 均为 [1, p-1], 且 start_index 必须小于等于 end_index
        if start_index > end_index || start_index < 1 || end_index > self.p_sub_one {
            error!("{}", SYS.get_info("err", "index_invalid"));
            exit(1)
        }

        // 转换成对应大数
        let big_p = Cyclic::parse_u128_to_big_num(self.p);
        let big_prim_root = Cyclic::parse_u128_to_big_num(self.prim_root);
        let big_start = Cyclic::parse_u128_to_big_num(start_index);
        let big_end  = Cyclic::parse_u128_to_big_num(end_index);

        // 计算 根据当前乘法群遍历到的 第一个目标(索引) 和 最后一个目标  prim_root^(start) % p
        let big_first = big_prim_root.modpow(&big_start, &big_p);
        let big_last  = big_prim_root.modpow(&big_end, &big_p);

        Self {
            p: self.p,
            prim_root: self.prim_root,
            p_sub_one: self.p_sub_one,

            current:Cyclic::parse_big_num_to_u128(big_first),
            last:Cyclic::parse_big_num_to_u128(big_last),

            bits_for_port: self.bits_for_port,
            base_ip_val: self.base_ip_val,
            ip_move_len: self.ip_move_len.clone(),
            port_move_len: self.port_move_len,

            valid_range: self.valid_range,

            tar_port_num: self.tar_port_num,

            tar_ports: self.tar_ports.clone(),
        }

    }


    /// 初始化全部扫描范围
    #[allow(dead_code)]
    pub fn init_whole(&self) -> Self {
        self.init(1, self.p_sub_one)
    }

}