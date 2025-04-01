mod new;
mod execute;




use std::sync::Arc;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::modes::Helper;
use crate::modules::probe_modules::active_probe_ipv6_code::CodeProbeModV6;
use crate::modules::target_iterators::IPv6PortSpaceTree;
use crate::SYS;



#[derive(Clone)]
pub struct Asset6 {

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

    // ipv6_port 空间树
    pub addr_port_space_tree:IPv6PortSpaceTree,
    
    // 是否开启别名检查
    pub aliased_prefixes_check:bool,
    
    // 单个地址最大允许开放的端口数量
    pub max_port_num:u16,
}


impl Helper for Asset6 {
    fn print_help() -> String {
        SYS.get_info("help", "Asset6")
    }
}