use std::process::exit;
use bitvec::bitvec;
use bitvec::macros::internal::funty::Fundamental;
use bitvec::vec::BitVec;
use log::error;
use crate::SYS;
use crate::tools::check_duplicates::{DuplicateCheckerV6, NotMarkedV6};

pub struct BitMapV6Pattern {
    map:BitVec,

    // 2^64 位
    last:bool,

    // 基础ip值
    base_ip_val:u128,
    // 掩码
    mask:u128,

    // 还原片段时的右移位数
    move_len:Vec<(u32,u32,u32)>,

    max_val:u128,
}

impl DuplicateCheckerV6 for BitMapV6Pattern {
    #[inline]
    fn set(&mut self, ip: u128) {
        let cur_base_ip = ip & self.mask;
        if self.base_ip_val != cur_base_ip {
            // 如果当前ip在模式字符串指定的范围之外
            // 什么也不做
            return
        }

        // 将 ip 转化为 ip索引, 起始地址的索引为0, 以后顺序加一
        let ip_index = self.ip_to_val(ip);

        if ip_index < self.max_val {
            self.map.set(ip_index as usize, true);
        } else if ip_index == self.max_val {
            self.last = true;
        } else {
            // ip值超过64位, 报错
            error!("{} {}", SYS.get_info("err", "bitmap_get_target_failed"), ip_index);
            exit(1)
        }
    }

    #[inline]
    fn not_marked_and_valid(&self, ip: u128) -> bool {
        let cur_base_ip = ip & self.mask;
        if self.base_ip_val != cur_base_ip {
            // 如果当前ip在模式字符串指定的范围之外
            return false
        }

        // 将 ip 转化为 ip索引, 起始地址的索引为0, 以后顺序加一
        let ip_index = self.ip_to_val(ip);

        if ip_index < self.max_val {

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

        } else if ip_index == self.max_val {

            !self.last

        } else {
            // 得到的ip值大于64位, 说明出错了
            error!("{} {}", SYS.get_info("err", "bitmap_get_target_failed"), ip_index);
            exit(1)
        }
    }
}


impl BitMapV6Pattern {

    pub fn new(bits_num:u32, base_ip_val:u128, mask:u128, parts:Vec<(u32, u32)>) -> Self {

        if (u64::MAX as u128) > (usize::MAX as u128) {

            // 不能安全地将 u64 转化为 usize
            error!("{}", SYS.get_info("err", "bitmap_u64_to_usize_err"));
            exit(1)
        }

        let capacity;
        if bits_num < 64 {
            capacity = 1usize << bits_num;
        } else if bits_num == 64 {
            // 如果模式字符达到64位
            capacity = u64::MAX as usize;
        } else {
            error!("{}", SYS.get_info("err", "pattern_char_over_64"));
            exit(1)
        }

        Self  {
            map: bitvec![0; capacity],
            last: false,
            base_ip_val,
            mask,
            move_len: Self::get_move_len(parts),
            max_val: u64::MAX as u128,
        }
    }




    /// 将接收到的ip地址转化为对应的ip特征值
    #[inline]
    fn ip_to_val(&self, ip:u128) -> u128 {

        let mut cur_ip_val:u128 = 0;
        for cur_move in self.move_len.iter() {
            let cur_part_val =  ((ip << cur_move.0) >> cur_move.1) << cur_move.2;
            cur_ip_val = cur_ip_val | cur_part_val;
        }

        cur_ip_val
    }


    #[allow(dead_code)]
    #[inline]
    pub fn match_patter(&self, ip:u128) -> bool {

        let cur_base_ip = ip & self.mask;
        if self.base_ip_val == cur_base_ip {
            // 如果当前ip符合模式字符串
            true
        } else {
            // 如果当前ip在模式字符串指定的范围之外
            false
        }
    }



    pub fn get_move_len(mut parts:Vec<(u32, u32)>) -> Vec<(u32, u32, u32)> {

        // [       |  part1  |       |  part2  |       | part3 |  ]
        // =>
        // 左移位数为: 128 - part(长度) - part偏移量
        // [ part3 |            ]
        // [ part2 |            ]
        // [ part1 |            ]
        // 右移位数为: 128 - part(长度)
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

            move_len.push((128 - part.0 - part.1, 128 - part.0, pre_len));
            pre_len += part.0
        }

        move_len
    }

}

impl NotMarkedV6 for BitMapV6Pattern {
    fn is_not_marked(&self, ip: u128) -> bool {
        // 将 ip 转化为 ip索引, 起始地址的索引为0, 以后顺序加一
        let ip_index = self.ip_to_val(ip);

        if ip_index < self.max_val {

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

        } else if ip_index == self.max_val {

            !self.last

        } else {
            // 得到的ip值大于64位, 说明出错了
            error!("{} {}", SYS.get_info("err", "bitmap_get_target_failed"), ip_index);
            exit(1)
        }
    }
}