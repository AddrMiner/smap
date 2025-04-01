use crate::tools::encryption_algorithm::hash::fnv1;

pub struct PCStable {
    pub stub:u64,   // 固定前缀部分
    pub mask:u64,   // 地址生成掩码
    pub reward:u64, // 获得的响应次数
    pub offset:u64, // 偏移量
}


impl PCStable {


    /// 在当前前缀下 生成具体的探测目标
    /// 注意: 地址hop对
    pub fn gen_target(&mut self, index:u32) -> (u64, u8, Vec<u8>) {

        let t_bits = fnv1(self.offset);

        // 使用 t_bits的后5位 生成 目标ttl
        let hop_limit = ((t_bits & 0x1f) as u8) + 3;

        // 生成目标前缀   固定前缀 | t_bits的前几位
        let tar_prefix = self.stub | ((t_bits >> 5) & self.mask);

        self.offset += 1;

        let be_bytes = index.to_be_bytes();

        (tar_prefix, hop_limit, vec![be_bytes[1], be_bytes[2], be_bytes[3]])
    }
    
    
    /// 以固定的跳数限制生成目标
    pub fn gen_edge_target(&mut self, index:u32, hop_limit:u8) -> (u64, u8, Vec<u8>) {

        let t_bits = fnv1(self.offset);

        // 生成目标前缀   固定前缀 | t_bits的前几位
        let tar_prefix = self.stub | (t_bits & self.mask);

        self.offset += 1;
        
        let be_bytes = index.to_be_bytes();

        (tar_prefix, hop_limit, vec![be_bytes[1], be_bytes[2], be_bytes[3]])
    }
    
    
    pub fn gen_topo_target(&mut self, index:u32) -> Vec<(u64, u8, Vec<u8>)> {
        // 保存由当前前缀生成的所有探测目标
        let mut topo_targets:Vec<(u64, u8, Vec<u8>)> = Vec::with_capacity(32);
        
        // 生成散列值
        let t_bits = fnv1(self.offset);
        // 生成目标前缀   固定前缀 | t_bits的前几位
        let tar_prefix = self.stub | (t_bits & self.mask);
        
        // 根据前缀索引生成 自定义编码
        let be_bytes = index.to_be_bytes();
        let code = vec![be_bytes[1], be_bytes[2], be_bytes[3]];
        
        // 对应同一个前缀, 生成 1到32为范围的ttl
        for cur_hop_limit in 1..33 {
            topo_targets.push((tar_prefix, cur_hop_limit, code.clone()));
        }

        self.offset += 1;
        
        topo_targets
    }
}

