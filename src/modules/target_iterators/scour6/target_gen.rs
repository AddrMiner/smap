use crate::modules::target_iterators::scour6::pcs_plus_table::PcsState;
use crate::modules::target_iterators::scour6::PCSPlusTable;
use crate::tools::encryption_algorithm::hash::fnv1;
use crate::tools::others::bit::find_nth_one;

impl PCSPlusTable {


    /// 在当前前缀下 生成具体的探测目标
    /// 注意: 地址hop对
    pub fn gen_target(&mut self, start_ttl:u8) -> (u64, u8) {
        // 按照当前状态选择生成方法
        match self.pcs_state {
            PcsState::FIRST => self.gen_tar_first(start_ttl),
            PcsState::SECOND => self.gen_tar_second(start_ttl),
            PcsState::THIRD => self.gen_tar_third(start_ttl),
        }
    }


    pub fn gen_tar_first(&mut self, start_ttl:u8) -> (u64, u8) {
        // 如果该前缀从未分裂过
        // 生成 随机值
        let t_bits = fnv1(self.offset);
        self.offset += 1;

        // 生成目标前缀   固定前缀 | t_bits的前几位
        let tar_prefix = self.stub | ((t_bits >> 5) & self.mask);

        // 使用 t_bits的后5位 生成 目标ttl
        // 注意: 生成范围 [start_ttl, start_ttl+31]
        let hop_limit = ((t_bits & 0x1f) as u8) + start_ttl;

        // 增加实际生成的目标数量
        self.gen_num += 1;

        (tar_prefix, hop_limit)
    }


    pub fn gen_tar_second(&mut self, start_ttl:u8) -> (u64, u8) {
        let mut fail_count = 0u32;
        loop {
            // 生成 随机值
            let t_bits = fnv1(self.offset);
            self.offset += 1;

            // 生成目标前缀   固定前缀 | t_bits的前几位
            let tar_prefix = self.stub | ((t_bits >> 5) & self.mask);

            // 当前分裂点的子前缀
            let cur_sub_prefix = tar_prefix >> self.sub_split_move_len;

            if let Some(cur_bit_map) = self.cur_sub_prefix_info.get(&cur_sub_prefix) {

                // 计算需要生成的目标范围数量
                let tar_range_num = cur_bit_map.count_ones();

                // 根据目标范围数量生成对应掩码
                let cur_mask = (tar_range_num.next_power_of_two() - 1) as u8;

                // t_bits的后5位, 初始生成值
                let pre_hop = (t_bits & 0x1f) as u8;

                if Self::range_is_true(pre_hop, cur_mask) {
                    // 如果直接在范围中

                    if let Some(c) = find_nth_one(*cur_bit_map, pre_hop) {
                        self.gen_num += 1;
                        return (tar_prefix, start_ttl+c)
                    }
                } else {
                    // 如果不在范围, 需要将生成的ttl转移到限制范围
                    let cur_hop_index = pre_hop & cur_mask;

                    if let Some(c) = find_nth_one(*cur_bit_map, cur_hop_index) {
                        let cur_hop = start_ttl + c;

                        let cur_target = (tar_prefix, cur_hop);

                        self.gen_num += 1;

                        // 记录被转移ttl的目标
                        self.repeat_targets.push(cur_target);

                        return cur_target
                    }
                }
            }

            fail_count += 1;
            if fail_count > 32 { return (0, 0) }
        }
    }


    pub fn gen_tar_third(&mut self, start_ttl:u8) -> (u64, u8) {
        let mut fail_count = 0u32;
        let max_offset = self.mask + 2;
        while (self.offset >> 5) < max_offset {
            // 生成 随机值
            let t_bits = fnv1(self.offset);
            self.offset += 1;

            // 生成目标前缀   固定前缀 | t_bits的前几位
            let tar_prefix = self.stub | ((t_bits >> 5) & self.mask);

            // 当前分裂点的子前缀
            let cur_sub_prefix = tar_prefix >> self.sub_split_move_len;

            if let Some(cur_bit_map) = self.cur_sub_prefix_info.get(&cur_sub_prefix) {
                // 计算需要生成的目标范围数量
                let tar_range_num = cur_bit_map.count_ones();
                // 根据目标范围数量生成对应掩码
                let cur_mask = (tar_range_num.next_power_of_two() - 1) as u8;

                // t_bits的后5位, 初始生成值
                let pre_hop = (t_bits & 0x1f) as u8;

                if Self::range_is_true(pre_hop, cur_mask) {
                    // 注意: 第三阶段时必须符合范围才能生成

                    if let Some(c) = find_nth_one(*cur_bit_map, pre_hop) {
                        let cur_hop = start_ttl + c;

                        let cur_target = (tar_prefix, cur_hop);

                        // 即便符合范围, 也可能存在重复, 必须无重复才行
                        if !self.repeat_tar_hashmap.contains(&cur_target) {
                            self.gen_num += 1;
                            return cur_target
                        }
                    }
                }
            }

            fail_count += 1;
            if fail_count > 256 { return (0, 0) }
        }
        (0, 0)
    }
    
    
    
}