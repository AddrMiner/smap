mod new;
mod tools;
mod execute;

use std::sync::Arc;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::modes::Helper;
use crate::modules::probe_modules::probe_mod_v6::ProbeModV6;
use crate::SYS;

pub struct PmapFileV6 {

    pub base_conf:Arc<BaseConf>,
    pub sender_conf:Arc<SenderBaseConf>,
    pub receiver_conf:Arc<ReceiverBaseConf>,
    pub probe:Arc<ProbeModV6>,

    // 预算
    pub pmap_budget:u32,
    // 推荐轮次
    pub pmap_batch_num:u64,
    // 是否允许概率相关图进行迭代
    pub pmap_allow_graph_iter:bool,

    // 文件路径
    pub path:String,

    // 抽样比例
    pub sampling_pro:f64,
    // 最小抽样数量
    pub min_sample_num:usize,
    
    // 目标端口
    pub tar_ports:Vec<u16>,

    // 端口数量限制
    // 开放端口超过该限制的地址将被视为异常地址, 不参与概率相关图训练
    pub port_num_limit:usize,
}

impl Helper for PmapFileV6 {
    fn print_help() -> String {
        SYS.get_info("help", "PmapFileV6")
    }
}