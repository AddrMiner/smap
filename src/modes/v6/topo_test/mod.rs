use std::sync::Arc;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::modules::probe_modules::topology_probe::topo_mod_v6::TopoModV6;
use crate::modules::target_iterators::IPv6FixedPrefixTree;

mod execute;
mod new;


/// 双树测试, 注意仅用于测试
pub struct DoubleTreeTest {

    // 探测器基础配置
    pub base_conf:Arc<BaseConf>,
    pub sender_conf:Arc<SenderBaseConf>,
    pub receiver_conf:Arc<ReceiverBaseConf>,

    // 发送数据包的总预算
    pub budget:u64,

    // 最大ttl
    pub max_ttl:u8,

    // ipv6拓扑探测模块
    pub probe:Arc<TopoModV6>,

    // ipv6前缀树
    pub prefix_tree:IPv6FixedPrefixTree,

    // 初始ttl
    pub initial_ttl:u8,
    // 最大沉默次数
    pub gap_limit:u8,
    // 拓扑探测过程单次最小目标数量
    pub min_target_num:usize,
}