use std::mem::take;
use ahash::{AHashMap, AHashSet};
use crate::modules::target_iterators::scour6::pcs_plus_table::PcsState;
use crate::modules::target_iterators::scour6::PCSPlusTable;

impl  PCSPlusTable {

    /// 检查前缀信息块状态                                                     // max_move_len 与 采样幂数相等, 比如2^7
    pub fn check(&mut self, all_nodes:&AHashMap<u128, u8>, max_move_len:u8, start_ttl:u8, expand_ttl_b:u32, expand_ttl_a:u32) {
        match self.pcs_state {
            PcsState::FIRST => self.check_first(max_move_len, all_nodes, start_ttl, expand_ttl_b, expand_ttl_a),
            PcsState::SECOND => self.check_second(max_move_len, all_nodes, start_ttl, expand_ttl_b, expand_ttl_a),
            PcsState::THIRD => self.check_third(all_nodes, start_ttl, expand_ttl_b, expand_ttl_a),
        }
    }

    pub fn check_first(&mut self, max_move_len:u8, all_nodes:&AHashMap<u128, u8>, start_ttl:u8, expand_ttl_b:u32, expand_ttl_a:u32){
        if self.offset > self.next_split_dot {
            // 分割当前前缀
            self.split_sub_prefix(all_nodes, start_ttl, expand_ttl_b, expand_ttl_a);
            // 计算下一次分割点
            self.next_split_dot *= 2;

            if self.sub_split_move_len <= max_move_len {
                // 如果在第一状态下遇到 结束子前缀分裂 情况

                // 直接转换为 第三状态
                self.pcs_state = PcsState::THIRD;
            } else {
                // 如果能够分裂子前缀

                // 切换为第二状态
                self.pcs_state = PcsState::SECOND;
            }
        }
    }

    pub fn check_second(&mut self, max_move_len:u8, all_nodes:&AHashMap<u128, u8>, start_ttl:u8, expand_ttl_b:u32, expand_ttl_a:u32, ){
        if self.offset > self.next_split_dot {
            
            // 将前缀进1
            self.sub_split_move_len -= 1;

            // 分割子前缀
            self.split_sub_prefix(all_nodes, start_ttl, expand_ttl_b, expand_ttl_a);

            // 计算下一次分割点
            self.next_split_dot *= 2;
            
            // 如果下一次就是第三状态, 清理所有现存记录
            if self.sub_split_move_len <= max_move_len {
                // 清理 所有现存记录
                self.dest_info.clear();

                // 将第二阶段保存的重复目标转换成哈希表, 该哈希表永久不变
                let repeat_targets = take(&mut self.repeat_targets);
                let mut repeat_tar_hashmap:AHashSet<(u64, u8)> = AHashSet::new();
                
                let sub_split_move_len = self.sub_split_move_len;
                let cur_sub_prefix_info = &self.cur_sub_prefix_info;
                for (tar_prefix, tar_hop) in repeat_targets.into_iter() {
                    // 计算在当前状态下对应的子前缀
                    let cur_sub_prefix = tar_prefix >> sub_split_move_len;
                    // 如果查不到对应子前缀, 说明已经被剪枝
                    if let Some(c) = cur_sub_prefix_info.get(&cur_sub_prefix) {
                        // 判断当前跳数是否已经不可用
                        if nth_is_one_from_n(*c, tar_hop, start_ttl) {
                            // 如果仍旧被标记为可用状态
                            repeat_tar_hashmap.insert((tar_prefix, tar_hop));
                        }
                    }
                }

                repeat_tar_hashmap.shrink_to_fit();
                self.repeat_tar_hashmap = repeat_tar_hashmap;
                
                // 转移到 第三状态
                self.pcs_state = PcsState::THIRD;
            }
        }

    }

    pub fn check_third(&mut self, all_nodes:&AHashMap<u128, u8>, start_ttl:u8, expand_ttl_b:u32, expand_ttl_a:u32, ){
        if self.offset > self.next_split_dot {
            // 重新分割当前前缀
            self.split_sub_prefix(all_nodes, start_ttl, expand_ttl_b, expand_ttl_a);

            // 清理 所有现存记录
            self.dest_info.clear();

            // 计算下一次分割点
            self.next_split_dot *= 2;
        }
    }
    
    
}


#[inline]
fn nth_is_one_from_n(num:u32, n:u8, start_index:u8) -> bool {
    (num >> (n-start_index)) & 1 == 1
}