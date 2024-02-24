use std::process::exit;
use bitvec::bitvec;
use bitvec::macros::internal::funty::Fundamental;
use bitvec::vec::BitVec;
use log::error;
use crate::core::conf::tools::args_parse::target_iterator::TarIterBaseConf;
use crate::SYS;
use crate::tools::check_duplicates::DuplicateCheckerV6Port;

pub struct BitMapV6Port {
    start_ip:u128,
    end_ip:u128,
    bits_for_port:u32,

    map:BitVec,
    tar_ports_index:Box<[usize; 65536]>,
}


impl DuplicateCheckerV6Port for BitMapV6Port {
    #[inline]
    fn set(&mut self, ip: u128, port: u16) {
        let tar_port_index = self.tar_ports_index[port as usize];
        // 如果目标端口中不存在该端口
        if tar_port_index == usize::MAX { return }

        // 如果 ip 不在目标范围
        if ip < self.start_ip || ip > self.end_ip { return }

        // 将 ip 转化为 ip索引, 起始地址的索引为0, 以后顺序加一
        let ip_index = (ip - self.start_ip) as usize;

        // 将 ip索引 和 端口索引 合并为 位图索引
        let bit_map_index = (ip_index << self.bits_for_port) | tar_port_index;

        self.map.set(bit_map_index, true);
    }

    #[inline]
    fn not_marked_and_valid(&self, ip: u128, port: u16) -> bool {
        let tar_port_index = self.tar_ports_index[port as usize];
        // 如果目标端口中不存在该端口
        if tar_port_index == usize::MAX { return false }

        // 如果 ip 不在目标范围
        if ip < self.start_ip || ip > self.end_ip { return false }

        // 将 ip 转化为 ip索引, 起始地址的索引为0, 以后顺序加一
        let ip_index = (ip - self.start_ip) as usize;

        // 将 ip索引 和 端口索引 合并为 位图索引
        let bit_map_index = (ip_index << self.bits_for_port) | tar_port_index;

        match self.map.get(bit_map_index) {
            Some(tar ) => {
                tar.as_bool()
            }

            None => {
                // 获取目标出错
                error!("{} {}", SYS.get_info("err", "bitmap_get_target_failed"), bit_map_index);
                exit(1)
            }
        }
    }
}


impl BitMapV6Port {

    pub fn new(start_ip:u128, end_ip:u128, tar_ip_num:u64, mut tar_ports:Vec<u16>) -> Self {

        // 不能安全地将 u64 转化为 usize
        if (u64::MAX as u128) > (usize::MAX as u128) { error!("{}", SYS.get_info("err", "bitmap_u64_to_usize_err")); exit(1) }

        // 在检查重复时, 必须添加0端口，以应对特殊情况
        if !tar_ports.contains(&0) {
            tar_ports.push(0);
        }

        tar_ports.sort();
        let tar_ports_num = tar_ports.len();

        // 计算 ip 和 port 所需要的位数
        let bits_for_ip = TarIterBaseConf::bits_needed_u64(tar_ip_num);
        let bits_for_port = TarIterBaseConf::bits_needed_usize(tar_ports_num);
        let total_bits_num = bits_for_ip + bits_for_port;

        // 注意: 比特位数最高不得超过 63位
        // ipv4地址所需的最大位数为 32位, 目标端口所需的最大位数为 16位, 所以在这里进行检查是不必要的
        if total_bits_num > 63 { error!("{}", SYS.get_info("err", "total_bits_num_over_63"));  exit(1) }

        // 位图的总位数, 如总比特位数为2, 则位图总位数为 b100
        let total_num = 1usize << total_bits_num;

        // 目的端口索引数组
        // 例:  目的端口: [22, 80, 443]
        // 索引数组: [ -1  -1 ..  -1 |  0 | -1 .. -1 |  1  |  -1 ..  -1 |   2  |  -1..  ],  -1表示usize::MAX, 因为 usize一定大于等于u64, 所以端口索引一定取不到
        // index:     0   1 ..   21 | 22 | 23 .. 79 | 80  |  81 .. 442 | 443  |  444..
        let mut tar_ports_index = Box::new([usize::MAX; 65536]);

        let mut index:usize = 0;
        for tar_port in tar_ports.into_iter() {
            // 下标为 目的端口号   值为 序号index
            // 注意: index的有效范围为 0..<tar_ports_num
            // 以端口号为下标可得到对应序号,  不存在端口对应的值为 -1
            tar_ports_index[usize::from(tar_port)] = index;
            index += 1;
        }

        Self  {
            start_ip,
            end_ip,

            bits_for_port,
            map: bitvec![0; total_num],
            tar_ports_index,
        }
    }

}