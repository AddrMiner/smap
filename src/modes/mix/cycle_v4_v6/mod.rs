mod new;
mod execute;

use std::sync::Arc;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::modes::{Helper};
use crate::modules::probe_modules::probe_mod_v4::ProbeModV4;
use crate::modules::probe_modules::probe_mod_v6::ProbeModV6;
use crate::modules::target_iterators::{CycleIpv4Port, CycleIpv6Port};
use crate::SYS;
use crate::tools::blocker::ipv4_blocker::BlackWhiteListV4;
use crate::tools::blocker::ipv6_blocker::BlackWhiteListV6;


pub struct CycleV4V6 {
    pub base_conf:Arc<BaseConf>,

    pub target_iters_v4:Vec<CycleIpv4Port>,
    pub target_iters_v6:Vec<CycleIpv6Port>,

    pub v4_ranges:Vec<(u32, u32, u64)>,
    pub v6_ranges:Vec<(u128, u128, u64)>,

    pub sender_conf:Arc<SenderBaseConf>,
    pub receiver_conf:Arc<ReceiverBaseConf>,

    pub probe_v4:Arc<ProbeModV4>,
    pub probe_v6:Arc<ProbeModV6>,

    // 注意: 这里是 目标ip数量 * 目标端口数量
    pub tar_num_v4:u64,
    pub tar_num_v6:u64,

    pub assigned_target_range_v4:Vec<Vec<(u64,u64,u64)>>,
    pub assigned_target_range_v6:Vec<Vec<(u128,u128,u64)>>,

    pub blocker_v4:BlackWhiteListV4,
    pub blocker_v6:BlackWhiteListV6,

    pub ttl:Option<u8>,
}


impl  Helper  for CycleV4V6 {
    fn print_help() -> String {
        SYS.get_info("help", "CycleV4V6")
    }
}