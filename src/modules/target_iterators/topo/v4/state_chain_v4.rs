use std::process::exit;
use bitvec::bitvec;
use bitvec::macros::internal::funty::Fundamental;
use bitvec::prelude::BitVec;
use log::error;
use crate::modules::output_modules::OutputMethod;
use crate::modules::probe_modules::topology_probe::topo_mod_v4::TopoMethodV4;
use crate::SYS;
use crate::tools::check_duplicates::bit_map::BitMapV4Pattern;

pub struct  TopoStateChainV4 {

    // 基础ip值
    base_ip_val:u32,
    // 掩码
    mask:u32,

    // 还原片段时的右移位数
    move_len:Vec<(u32,u32,u32)>,

    //     [ 地址1                              , 地址2, ...  ]
    //     [ u8(  下一个ttl | 是否接收到响应(1比特)), u8, ....   ]
    // 注意: 已接收响应为1, 未接收响应为0
    pub state_chain:Vec<u8>,

    // 待探测的 目标总数
    pub target_count:u32,
    
    // 记录整个ipv4空间的位图
    pub bit_map:BitVec,

    // 还原 真实ip 时的右移位数
    ip_move_len:Vec<(u32,u32,u32)>
}


impl TopoStateChainV4 {

    // 如果在 目标地址范围之中, 返回 true
    pub fn in_range(&self, ip: u32) -> bool {
        self.base_ip_val == (ip & self.mask)
    }

    // 目标ip地址 -> ip索引
    pub fn get_ip_index(&self, ip: u32) -> u32 {
        self.ip_to_val(ip)
    }

    // 在 预扫描 中标记ip, 并 写入下一个ttl
    pub fn set_next_ttl(&mut self, ip_index: usize, next_ttl:u8) {

        //     [ u8(  下一个ttl | 是否接收到响应(1比特)), u8, ....   ]
        self.state_chain[ip_index] = next_ttl << 1;
    }
    
    // 在 拓扑扫描 中标记ip, 写入下一个ttl, 并标记状态
    pub fn set_next_ttl_state(&mut self, ip_index: usize, next_ttl:u8) {

        //     [ u8(  下一个ttl | 是否接收到响应(1比特)), u8, ....   ]
        self.state_chain[ip_index] = (next_ttl << 1) | 1;
    }
    
    pub fn close_cur_tar_ip(&mut self, ip_index: usize) {

        //  设为0, 表示 永远终止 对 该目标ip 的探测
        self.state_chain[ip_index] = 0;
    }

    // 未被标记, 注意: 这里输入的是 ip
    pub fn not_marked(&self, ip: usize) -> bool {
        match self.bit_map.get(ip) {
            Some(tar) => {
                tar.as_bool()
            }

            None => {
                // 获取目标出错
                error!("{} {}", SYS.get_info("err", "bitmap_get_target_failed"), ip);
                exit(1)
            }
        }
    }


}

impl TopoStateChainV4 {

    pub fn new(bits_num:u32, base_ip_val:u32, mask:u32, parts:Vec<(u32, u32)>, ip_move_len:Vec<(u32,u32,u32)>) -> Self {

        if (u64::MAX as u128) > (usize::MAX as u128) {
            // 不能安全地将 u64 转化为 usize
            error!("{}", SYS.get_info("err", "bitmap_u64_to_usize_err"));
            exit(1)
        }

        Self  {
            base_ip_val,
            mask,
            move_len: BitMapV4Pattern::get_move_len(parts),

            state_chain: vec![0; 1usize << bits_num],
            target_count: 0,
            bit_map: bitvec![0; 1usize << 32],
            ip_move_len,
        }
    }

    /// 将接收到的ip地址转化为对应的ip特征值
    #[inline]
    fn ip_to_val(&self, ip:u32) -> u32 {

        let mut cur_ip_val:u32 = 0;
        for cur_move in self.move_len.iter() {
            let cur_part_val =  ((ip << cur_move.0) >> cur_move.1) << cur_move.2;
            cur_ip_val = cur_ip_val | cur_part_val;
        }

        cur_ip_val
    }

  
    /// 打印 未响应的目标
    pub fn print_silent_target(&mut self, probe:&Box<dyn TopoMethodV4>, output:&mut Box<dyn OutputMethod>) {

        let mut active_count:u32 = 0;

        let state_chain_len = self.state_chain.len();
        let base_ip_val = self.base_ip_val;
        let ip_move_len = self.ip_move_len.clone();
        for i_usize in 0..state_chain_len {

            let state_code = self.state_chain[i_usize];
            if state_code == 0 {
                // 如果 该目的地址 未被标记, 直接跳过该地址
                // 只有 自身存活 或者 引起同一网络中其他主机回复的地址才是有效探测目标
                continue
            }

            // 统计 需要进行探测的目标数量, 也即 被标记的目标数量
            active_count += 1;
            
            // 判断 当发送轮次是否接收到响应
            if (state_code & 1) == 0 {
                // 未接收响应

                // 根据索引计算出 真实ip
                let i_u32 = i_usize as u32;
                let mut dest_ip = base_ip_val;
                for part_move in ip_move_len.iter() {
                    // (0: 第一次左移位数, 1: 右移位数, 2: 第二次左移位数)
                    let cur_part = ((i_u32 << part_move.0) >> part_move.1) << part_move.2;
                    dest_ip = dest_ip | cur_part;
                }
                
                // 从 状态编码 中提取 当次探测的目标ttl
                let tar_ttl = state_code >> 1;

                // 输出该条目信息
                output.writer_line(&probe.print_silent_record(dest_ip, tar_ttl));
                
                // 将next_ttl写入
                // 如果 next_ttl 等于 1, 下一ttl将自动置为 0
                self.state_chain[i_usize] = (tar_ttl - 1) << 1;
                
            } else {
                // 已接收响应
                
                // 将 标志 重置为 未接收响应, 等待下一次发送
                self.state_chain[i_usize] &= 0b1111_1110;
            }
        }
        self.target_count = active_count
    }
}



