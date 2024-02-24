use std::process::exit;
use bitvec::bitvec;
use bitvec::macros::internal::funty::Fundamental;
use bitvec::vec::BitVec;
use log::error;
use crate::SYS;
use crate::tools::check_duplicates::DuplicateCheckerV4;

pub struct BitMapV4Pattern {
    map:BitVec,

    // 基础ip值
    base_ip_val:u32,
    // 掩码
    mask:u32,

    // 还原片段时的右移位数
    move_len:Vec<(u32,u32,u32)>,
}

impl DuplicateCheckerV4 for BitMapV4Pattern {
    #[inline]
    fn set(&mut self, ip: u32) {
        let cur_base_ip = ip & self.mask;
        if self.base_ip_val != cur_base_ip {
            // 如果当前ip在模式字符串指定的范围之外
            // 什么也不做
            return
        }

        // 将 ip 转化为 ip索引, 起始地址的索引为0, 以后顺序加一
        let ip_index = self.ip_to_val(ip);

        self.map.set(ip_index as usize, true);
    }

    #[inline]
    fn not_marked_and_valid(&self, ip: u32) -> bool {
        let cur_base_ip = ip & self.mask;
        if self.base_ip_val != cur_base_ip {
            // 如果当前ip在模式字符串指定的范围之外
            return false
        }

        // 将 ip 转化为 ip索引, 起始地址的索引为0, 以后顺序加一
        let ip_index = self.ip_to_val(ip);

        match self.map.get(ip_index as usize) {
            Some(tar ) => {
                tar.as_bool()
            }

            None => {
                // 获取目标出错
                error!("{} {}", SYS.get_info("err", "bitmap_get_target_failed"), ip_index);
                exit(1)
            }
        }
    }
}


impl BitMapV4Pattern {

    #[allow(dead_code)]
    pub fn new(bits_num:u32, base_ip_val:u32, mask:u32, parts:Vec<(u32, u32)>) -> Self {

        if (u64::MAX as u128) > (usize::MAX as u128) {

            // 不能安全地将 u64 转化为 usize
            error!("{}", SYS.get_info("err", "bitmap_u64_to_usize_err"));
            exit(1)
        }

        let capacity= 1usize << bits_num;

        Self  {
            map: bitvec![0; capacity],
            base_ip_val,
            mask,
            move_len: Self::get_move_len(parts),
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

    pub fn get_move_len(mut parts:Vec<(u32, u32)>) -> Vec<(u32, u32, u32)> {

        // [       |  part1  |       |  part2  |       | part3 |  ]
        // =>
        // 左移位数为: 32 - part(长度) - part偏移量
        // [ part3 |            ]
        // [ part2 |            ]
        // [ part1 |            ]
        // 右移位数为: 32 - part(长度)
        // =>
        // [       |    part3   ]
        // [       |    part2   ]
        // [       |    part1   ]
        // =>
        // 左移位数为: 已经存放的其他片段位数之和
        // [          | part1 | part2 | part3 ]

        parts.reverse();

        let mut move_len:Vec<(u32, u32, u32)> = vec![];

        let mut pre_len = 0;
        for part in parts {

            move_len.push((32 - part.0 - part.1, 32 - part.0, pre_len));
            pre_len += part.0
        }

        move_len
    }

}