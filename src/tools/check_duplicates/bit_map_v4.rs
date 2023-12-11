use std::process::exit;
use bitvec::bitvec;
use bitvec::macros::internal::funty::Fundamental;
use bitvec::vec::BitVec;
use log::error;
use crate::SYS;

#[allow(dead_code)]
pub struct BitMapV4 {
    start_ip:u32,
    end_ip:u32,
    map:BitVec
}


impl BitMapV4 {

    #[allow(dead_code)]
    pub fn new(start_ip:u32, end_ip:u32, tar_ip_num:u64) -> Self {

        if (u64::MAX as u128) > (usize::MAX as u128) {

            // 不能安全地将 u64 转化为 usize
            error!("{}", SYS.get_info("err", "bitmap_u64_to_usize_err"));
            exit(1)
        }


        Self  {
            start_ip,
            end_ip,
            map: bitvec![0; tar_ip_num as usize],
        }
    }

    /// 对ip进行存在标记
    #[allow(dead_code)]
    #[inline]
    pub fn set(&mut self, ip:u32) {

        if ip < self.start_ip || ip > self.end_ip {
            // 如果 ip 不在目标范围
            // 什么也不做
            return
        }

        // 将 ip 转化为 ip索引, 起始地址的索引为0, 以后顺序加一
        let ip_index = (ip - self.start_ip) as usize;

        self.map.set(ip_index, true);
    }



    /// 如果 没被标记 ,返回true
    /// 如果被标记或超出目标范围,返回false
    #[allow(dead_code)]
    #[inline]
    pub fn not_marked_and_valid(&self, ip:u32) -> bool {

        if ip < self.start_ip || ip > self.end_ip {
            // 如果不在目标范围内
            // 直接返回false
            return false
        }

        // 将 ip 转化为 ip索引, 起始地址的索引为0, 以后顺序加一
        let ip_index = (ip - self.start_ip) as usize;

        match self.map.get(ip_index) {
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


    /*
    /// 检查ip是否无效或被标记
    /// 如果ip不在目标范围内, 直接返回true
    /// 如果被标记, 直接返回true
    /// 如果没被标记, 对ip进行标记后返回false
    #[inline]
    pub fn check_invalid_repeat_and_set(&mut self, ip:u32) -> bool {

        if ip < self.start_ip || ip > self.end_ip {
            // 如果ip不在目标范围
            // 直接返回 true
            return true
        }

        // 将 ip 转化为 ip索引, 起始地址的索引为0, 以后顺序加一
        let ip_index = (ip - self.start_ip) as usize;

        match self.map.get_mut(ip_index) {
            Some(mut tar) => {
                if tar.as_bool() {

                    // 如果没被标记, 将目标标记后返回false
                    *tar = true;
                    false
                } else {

                    // 如果存在, 直接返回true
                    true
                }
            }
            None => {

                // 无法获取到目标
                error!("{} {}", SYS.get_info("err", "bitmap_get_target_failed"), ip_index);
                exit(1)
            }
        }
    }*/

}