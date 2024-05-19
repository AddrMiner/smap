use std::sync::Arc;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::modes::Helper;
use crate::modes::v6::space_tree::new::SpaceTreeType;
use crate::modules::probe_modules::active_probe_ipv6_code::CodeProbeModV6;
use crate::modules::target_iterators::IPv6SpaceTree;
use crate::SYS;

mod new;
mod execute;




pub struct SpaceTree6 {

    // 探测器基础配置
    pub base_conf:Arc<BaseConf>,
    pub sender_conf:Arc<SenderBaseConf>,
    pub receiver_conf:Arc<ReceiverBaseConf>,
    
    // 进行 区域编码 的 ipv6探测模块
    pub probe:Arc<CodeProbeModV6>,
    
    // 目标生成 总预算
    pub budget:u64,
    
    // 每轮次的预算
    pub batch_size:u64,
    
    // 空间树类型
    pub space_tree_type:SpaceTreeType,
    
    // ipv6空间树
    pub space_tree:IPv6SpaceTree,
    
}

impl Helper for SpaceTree6 {
    fn print_help() -> String {
        SYS.get_info("help", "SpaceTree6")
    }
}