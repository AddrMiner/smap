
use crate::modules::target_iterators::{CycleIpv4};
use crate::modules::target_iterators::pmap::ip::IpStruct;


pub struct PmapIterV4 {

    // ipv4 地址迭代器(引导迭代器)
    pub ipv4_guide_iter:CycleIpv4,

    // 引导迭代器的 起始状态索引, 用于重置 引导迭代器
    iter_start_current_last:(u64, u64),

    // ipv4(u32) -> ip结构体
    pub ip_map:Vec<IpStruct>,


}

impl PmapIterV4 {

    pub fn new(capacity:usize, ipv4_guide_iter:CycleIpv4) -> Self {

        // 初始状态下的 current索引 和 last索引, 用于重置 引导迭代器 的状态
        let iter_start_current_last = (ipv4_guide_iter.current, ipv4_guide_iter.last);

        Self {
            ipv4_guide_iter,
            iter_start_current_last,
            ip_map: vec![IpStruct::new(); capacity],
        }
    }

    pub fn reset_guide_iter(&mut self) {
        self.ipv4_guide_iter.current = self.iter_start_current_last.0;
        self.ipv4_guide_iter.last = self.iter_start_current_last.1;
    }
}