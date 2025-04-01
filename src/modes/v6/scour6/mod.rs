use std::sync::Arc;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::modes::Helper;
use crate::modules::probe_modules::topo_mod_v6::CodeTopoProbeModV6;
use crate::SYS;

mod new;
mod execute;


pub struct Scour6 {
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
    
    // 扩展的ttl维度
    pub expand_ttl_b:u32,
    pub expand_ttl_a:u32,
    
    // 采样数量幂数
    pub sample_pow:u64,

    // 目标前缀文件路径
    pub path:String,
    
    // 汤姆森采样窗口
    pub window_size:u32,
    
    // 起始跳数
    pub start_hop_limit:u8,

    // 显示前缀数量
    pub show_prefix_num:usize,
}

impl Helper for Scour6 {
    fn print_help() -> String {
        SYS.get_info("help", "Scour6")
    }
}
