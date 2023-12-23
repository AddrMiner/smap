use ahash::AHashMap;
use crate::modules::target_iterators::pmap::ip::IpStruct;
use crate::tools::others::search::binary_search;

impl IpStruct {

    #[inline]
    pub fn get_label(&self) -> String {

        // 注意: 这里应该可以进行性能改进
        format!("{:?}", self.open_ports).trim_matches(|c| {c == '[' || c == ']'}).replace(" ", "")
    }



    /// 判断 目标端口 是否在 开放端口列表 或 非开放端口列表 中存在
    /// 如果 存在 返回 false, 如果 不存在 返回 true
    #[inline]
    pub fn port_is_avail(&self, port:&u16) -> bool {
        if binary_search(&self.open_ports, port) || binary_search(&self.not_open_ports, port) {
            return false
        }
        true
    }


    /// 不在 更新概率表, 且不在 已探开放端口列表 和 已探未开放端口列表中, 返回 true
    #[inline]
    pub fn port_is_avail_in_ab(&self, port:&u16, ptr_map:&AHashMap<u16, u16>) -> bool {
        !ptr_map.contains_key(port) && self.port_is_avail(port)
    }

}



