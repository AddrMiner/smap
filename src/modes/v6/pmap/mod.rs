use std::sync::Arc;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::modes::Helper;
use crate::modules::probe_modules::probe_mod_v6::ProbeModV6;
use crate::modules::target_iterators::{CycleIpv6Pattern};
use crate::SYS;
use crate::tools::blocker::ipv6_blocker::BlackWhiteListV6;

mod execute;
mod new;
mod tools;




pub struct PmapV6 {

    pub base_conf:Arc<BaseConf>,

    // 包含 预扫描 和 推荐扫描 的全部目标, 由预扫描最终索引进行分割
    // 注意: 该迭代器为 完全扫描阶段 的迭代器, 并用作 pmap迭代器 的引导迭代器
    // 在 推荐扫描 过程中, 使用 pmap迭代器, 在执行函数中定义
    pub tar_iter_without_port:CycleIpv6Pattern,
    //  完全(预扫描)阶段的最后一个索引, 其值加一为推荐扫描的第一个索引
    pub full_scan_last_index:u128,

    // 预算
    pub pmap_budget:u32,
    // 推荐轮次
    pub pmap_batch_num:u64,
    // 是否允许概率相关图进行迭代
    pub pmap_allow_graph_iter:bool,
    // 使用哈希集合而不是位图进行标记
    pub pmap_use_hash_recorder:bool,

    pub sender_conf:Arc<SenderBaseConf>,
    pub receiver_conf:Arc<ReceiverBaseConf>,
    pub probe:Arc<ProbeModV6>,

    pub tar_ip_num:u64,
    pub ip_bits_num:u32,
    pub base_ip_val:u128,
    pub mask:u128,
    pub parts:Vec<(u32, u32)>,
    pub tar_ports:Vec<u16>,

    pub blocker:BlackWhiteListV6,
}



impl Helper for PmapV6 {
    fn print_help() -> String {
        SYS.get_info("help", "PmapV6")
    }
}

