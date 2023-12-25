use std::process::exit;
use bitvec::bitvec;
use bitvec::macros::internal::funty::Fundamental;
use bitvec::vec::BitVec;
use log::error;
use crate::SYS;
use crate::tools::check_duplicates::{DuplicateCheckerV4, NotMarkedV4};

pub struct BitMapV4 {
    start_ip:u32,
    end_ip:u32,
    map:BitVec
}

impl DuplicateCheckerV4 for BitMapV4 {
    #[inline]
    fn set(&mut self, ip: u32) {
        if ip < self.start_ip || ip > self.end_ip {
            // 如果 ip 不在目标范围
            // 什么也不做
            return
        }

        // 将 ip 转化为 ip索引, 起始地址的索引为0, 以后顺序加一
        let ip_index = (ip - self.start_ip) as usize;

        self.map.set(ip_index, true);
    }

    #[inline]
    fn not_marked_and_valid(&self, ip: u32) -> bool {
        if ip < self.start_ip || ip > self.end_ip {
            // 如果不在目标范围内
            // 直接返回false
            return false
        }

        // 将 ip 转化为 ip索引, 起始地址的索引为0, 以后顺序加一
        let ip_index = (ip - self.start_ip) as usize;

        match self.map.get(ip_index) {
            Some(tar) => {
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


impl BitMapV4 {
    pub fn new(start_ip: u32, end_ip: u32, tar_ip_num: u64) -> Self {
        if (u64::MAX as u128) > (usize::MAX as u128) {
            // 不能安全地将 u64 转化为 usize
            error!("{}", SYS.get_info("err", "bitmap_u64_to_usize_err"));
            exit(1)
        }


        Self {
            start_ip,
            end_ip,
            map: bitvec![0; tar_ip_num as usize],
        }
    }
}

impl NotMarkedV4 for BitMapV4 {
    #[inline]
    fn is_not_marked(&self, ip: u32) -> bool {
        // 将 ip 转化为 ip索引, 起始地址的索引为0, 以后顺序加一
        let ip_index = (ip - self.start_ip) as usize;

        match self.map.get(ip_index) {
            Some(tar) => {
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




