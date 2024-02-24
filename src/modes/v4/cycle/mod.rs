
mod new;
mod execute;


use std::sync::Arc;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::modes::{Helper};
use crate::modules::probe_modules::probe_mod_v4::ProbeModV4;
use crate::modules::target_iterators::CycleIpv4Type;
use crate::SYS;
use crate::tools::blocker::ipv4_blocker::BlackWhiteListV4;

/// zmap_v4
pub struct CycleV4 {
    pub base_conf:Arc<BaseConf>,
    pub target_iter:CycleIpv4Type,
    pub sender_conf:Arc<SenderBaseConf>,
    pub receiver_conf:Arc<ReceiverBaseConf>,

    pub probe:Arc<ProbeModV4>,

    pub start_ip:u32,
    pub end_ip:u32,
    pub tar_ip_num:u64,
    
    pub ttl:Option<u8>,

    pub assigned_target_range:Vec<(u64,u64,u64)>,
    pub blocker:BlackWhiteListV4,
}


impl  Helper  for CycleV4 {
    fn print_help() -> String {

        SYS.get_info("help", "CycleV4")
    }
}
