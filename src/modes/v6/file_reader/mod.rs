mod new;
mod execute;


use std::sync::Arc;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::modes::{Helper};
use crate::modules::probe_modules::probe_mod_v6::ProbeModV6;
use crate::modules::target_iterators::TargetFileReader;
use crate::SYS;
use crate::tools::blocker::ipv6_blocker::BlackWhiteListV6;

/// zmap_v6
pub struct V6FileReader {
    pub base_conf:Arc<BaseConf>,
    pub target_iter:TargetFileReader,
    pub sender_conf:Arc<SenderBaseConf>,
    pub receiver_conf:Arc<ReceiverBaseConf>,

    pub probe:Arc<ProbeModV6>,

    // 注意: 这里为 目标ip数量 * 目标端口数量
    pub tar_num:Option<u64>,

    pub tar_ports:Vec<u16>,
    pub assigned_target_range:Vec<(u64, u64, u64)>,
    
    pub ttl:Option<u8>,

    pub blocker:BlackWhiteListV6,
}



impl  Helper  for V6FileReader {
    fn print_help() -> String {

        SYS.get_info("help", "V6FileReader")
    }
}