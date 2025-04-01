use std::cmp::min;
use std::net::Ipv6Addr;
use log::info;
use crate::modules::target_iterators::scour6::PCSPlusTable;
use crate::modules::target_iterators::Scour6Iter;

impl PCSPlusTable {
    
    /// 当所有预算都被耗尽, 清理所有冗余内存
    pub fn clear(&mut self){
        self.dest_info.clear();
        self.cur_sub_prefix_info.clear();
        self.repeat_targets.clear();
        self.repeat_tar_hashmap.clear();

        self.dest_info.shrink_to_fit();
        self.cur_sub_prefix_info.shrink_to_fit();
        self.repeat_targets.shrink_to_fit();
        self.repeat_tar_hashmap.shrink_to_fit();
        
        self.thompson_window.clear();
    }


    /// 如果是直接命中范围的返回true, 如果需要转移返回false
    #[inline]
    pub fn range_is_true(a:u8, mask:u8) -> bool {
        let c = a & !mask;
        c == 0
    }

    #[inline]
    pub fn get_prefix_code(index:u32) -> Vec<u8> {
        let be_bytes = index.to_be_bytes();
        vec![be_bytes[1], be_bytes[2], be_bytes[3]]
    }


    /// 记录位图u32, 范围:[3, 34]
    // #[inline]
    // pub fn set_pos_from_three(val: &mut u32, pos:u8) {
    //     // 注意: 范围为 [3,34]
    //     *val |= 1 << (pos - 3);
    // }

    #[inline]
    pub fn set_pos_from_n(val: &mut u32, pos:u8, start_index:u8) {
        // 注意: 范围为 [start_index, start_index+31]
        *val |= 1 << (pos - start_index);
    }


    /// 将最高位之上的n位标记为1
    /// 注意: 两个参数均不能为0
    #[inline]
    pub fn set_ones_above_msb(num:&mut u32, count: u32) {

        // 找到最高位1的位置
        let msb_pos = 31 - num.leading_zeros();

        // 计算可用的位数（最高位之上的位数）
        let available_bits = 31 - msb_pos;

        // 如果需要设置的1的数量超过可用位数，则只设置可用的位数
        let actual_count = count.min(available_bits);

        // 创建掩码：从msb后一位开始的count个1
        let mask = if actual_count > 0 {
            ((1u32 << actual_count) - 1) << (msb_pos + 1)
        } else {
            0
        };

        // 应用掩码
        *num |= mask
    }

    /// 注意: 两个参数均不能为0
    #[inline]
    pub fn set_ones_after_lsb(num: &mut u32, count: u32) {
        // 找到最低位1的位置(同时也是可用位数)
        let lsb_pos = num.trailing_zeros();

        // 如果需要设置的1的数量超过可用位数，则只设置可用的位数
        let actual_count = count.min(lsb_pos);

        // 创建掩码：从lsb后一位开始的count个1
        let mask = if actual_count > 0 {
            ((1u32 << actual_count) - 1) << (lsb_pos - actual_count)
        } else {
            0
        };

        // 应用掩码
        *num |= mask;
    }

    pub fn expand_to_power_of_two(num:u32) -> u32 {
        // 后置0的数量
        let left_move_len = num.trailing_zeros();

        // 根据当前范围推算的活跃数量
        let ones_num = 32 - left_move_len - num.leading_zeros();
        // 活跃数量调整为至少为2的整指数
        let ones_num = ones_num.next_power_of_two();

        if ones_num > 31 {
            u32::MAX << left_move_len
        } else {
            ((1u32 << ones_num) - 1) << left_move_len
        }
    }
}



impl Scour6Iter {

    pub fn print_offset_count(&self, top_count:usize) {
        
        let mut all_offset = 0;
        let mut total_count = 0;
        let mut offset_count = Vec::with_capacity(self.pcs_list.len());

        for (index, cur_pcs) in self.pcs_list.iter().enumerate() {
            let cur_offset = cur_pcs.gen_num;

            offset_count.push((index, cur_offset));
            total_count += cur_offset;
            
            if cur_pcs.not_finished {
                all_offset += cur_pcs.offset;
            } else { 
                all_offset += (cur_pcs.mask + 1) * 32;
            }
        }

        // 按 offset 值从大到小排序
        offset_count.sort_by(|a, b| b.1.cmp(&a.1));

        info!("total_count: {}", total_count);
        info!("all_offset: {}", all_offset);
        
        let top_count = min(top_count, offset_count.len());

        for i in 0..top_count {

            let cur_index = offset_count[i].0;
            let cur_offset = offset_count[i].1;
            let cur_pcs= &self.pcs_list[cur_index];

            let prefix = Ipv6Addr::from((cur_pcs.stub as u128) << 64);
            let prefix_len = cur_pcs.mask.leading_zeros();
            let cur_reward = cur_pcs.reward;

            let real_offset = cur_pcs.offset;
            let mask = cur_pcs.mask;

            info!("{}:  {:?}/{} offset: {}  {}% gen:{}   {}% reward:{}  {}%", i+1, prefix,
                prefix_len, real_offset, (real_offset as f64) / ((32 * mask) as f64) * 100.0,
                cur_offset, (cur_offset as f64) / (total_count as f64) * 100.0, cur_reward, (cur_reward as f64) / (cur_offset as f64) * 100.0 )
        }

    }
}