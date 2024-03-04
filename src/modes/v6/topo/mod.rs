
use std::sync::Arc;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::modes::Helper;
use crate::modules::probe_modules::topology_probe::topo_mod_v6::TopoModV6;
use crate::modules::target_iterators::CycleIpv6Pattern;
use crate::SYS;
use crate::tools::blocker::ipv6_blocker::BlackWhiteListV6;

mod new;
mod execute;
mod tools;

pub struct Topo6 {
    pub base_conf:Arc<BaseConf>,
    pub sender_conf:Arc<SenderBaseConf>,
    pub receiver_conf:Arc<ReceiverBaseConf>,

    pub probe:Arc<TopoModV6>,
    // ipv4 辅助拓扑探测模块(可选)
    pub sub_probe:Option<Arc<TopoModV6>>,

    pub ip_bits_num:u32,
    pub base_ip_val:u128,
    pub mask:u128,
    pub parts:Vec<(u32, u32)>,

    pub max_ttl:u8,

    pub tar_iter:CycleIpv6Pattern,

    pub blocker:BlackWhiteListV6,
}


impl Helper for Topo6 {
    fn print_help() -> String {

        SYS.get_info("help", "Topo6")
    }
}

