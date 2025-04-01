use std::sync::Arc;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::modules::probe_modules::topo_mod_v6::CodeTopoProbeModV6;

mod new;
mod execute;



pub struct TreeTrace6 {

    // 探测器基础配置
    pub base_conf:Arc<BaseConf>,
    pub sender_conf:Arc<SenderBaseConf>,
    pub receiver_conf:Arc<ReceiverBaseConf>,
    
    // 自定义编码的拓扑探测模块
    pub probe:Arc<CodeTopoProbeModV6>,

    // 目标生成 总预算
    pub budget:u64,

    // 每轮次的预算
    pub batch_size:u64,
    
    // 目标前缀文件路径
    pub path:String,
    
    // 是否强制为拓扑探测
    pub topo_scan:bool,
    
    // 显示前缀信息数量
    pub show_prefix_num:usize,
}