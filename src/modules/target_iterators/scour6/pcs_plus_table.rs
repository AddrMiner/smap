use ahash::{AHashMap, AHashSet};
use crate::modules::target_iterators::scour6::thompson_window::ThompsonWindow;

pub enum PcsState {
    FIRST,
    SECOND,
    THIRD
}

pub struct PCSPlusTable {
    pub stub:u64,   // 固定前缀部分
    pub mask:u64,   // 地址生成掩码
    pub reward:u64, // 获得的响应次数
    
    pub offset:u64, // 偏移量
    // 实际生成的目标数量
    pub gen_num:u64,
    
    // 当前 单一轮次 的生成目标数量
    pub cur_gen_num:u32,
    
    // 汤姆森窗口
    pub thompson_window:ThompsonWindow,

    // (目的前缀, 目的前缀的关联响应地址)
    pub dest_info:Vec<(u64, u128)>,
    
    // 当前子前缀分割维数
    // 初始状态为: 64 - 前缀长度, 如/48为16
    // 往后依次递减
    pub sub_split_move_len:u8,

    // 子前缀 -> 记录位图
    pub cur_sub_prefix_info:AHashMap<u64, u32>,
    
    // 下一次分割点, 当生成的总数量达到该点时会执行子前缀分割
    pub next_split_dot:u64,
    
    pub pcs_state:PcsState,
    
    // 第二阶段在这里保留 可能导致重复生成的目标
    pub repeat_targets:Vec<(u64, u8)>,
    // 第三阶段将上述还保留的目标转化为哈希表
    pub repeat_tar_hashmap:AHashSet<(u64, u8)>,
    
    pub not_finished:bool,
}

impl PCSPlusTable {
    
    /// 根据dest_info记录, 按指定维度进行分割
    pub fn split_sub_prefix(&mut self, all_nodes:&AHashMap<u128, u8>, start_ttl:u8, expand_ttl_b:u32, expand_ttl_a:u32, ){
        self.cur_sub_prefix_info.clear();
        self.cur_sub_prefix_info.shrink_to_fit();
        
        // 第一阶段: 子前缀 -> 记录位图u32 注意范围为[3, 34]
        // 第二阶段: 子前缀 -> 扩展位图, 对于所有非0的位图, 在最高的1位上扩展n位
        let mut sub_prefix_info:AHashMap<u64, u32> = AHashMap::new();
        
        // 第一阶段
        let sub_split_move_len = self.sub_split_move_len;
        for (cur_prefix, assoc_responder) in self.dest_info.iter() {
            // 遍历当前大前缀下每个已经发送的目标前缀
            
            // 计算 当前子前缀
            let cur_sub_prefix = cur_prefix >> sub_split_move_len;
            
            // 当前目标前缀关联的响应者的最小响应跳数
            let assoc_hop_limit = *all_nodes.get(assoc_responder).unwrap();
            
            if let Some(bit_map) = sub_prefix_info.get_mut(&cur_sub_prefix) {
                // 如果当前子前缀已被记录

                // 注意: hop_limit范围为 [start_ttl, start_ttl+31]
                Self::set_pos_from_n(bit_map, assoc_hop_limit, start_ttl);
                
            } else {
                // 如果当前子前缀未被记录
                let mut bit_map = 0u32;
                Self::set_pos_from_n(&mut bit_map, assoc_hop_limit, start_ttl);
                
                sub_prefix_info.insert(cur_sub_prefix, bit_map);
            }
        }
        
        let expand_before = expand_ttl_b > 0;
        let expand_after = expand_ttl_a > 0;
        
        // 第二阶段
        for (_, bit_map) in sub_prefix_info.iter_mut() {
            
            // 扩展前位
            if expand_before {
                Self::set_ones_after_lsb(bit_map, expand_ttl_b);
            }
            
            // 扩展后位
            if expand_after {
                Self::set_ones_above_msb(bit_map, expand_ttl_a);
            }
            
            // 扩展为2的整幂数
            *bit_map = Self::expand_to_power_of_two(*bit_map);
        }
        
        self.cur_sub_prefix_info = sub_prefix_info;
    }
    
}


