use std::sync::Arc;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::modes::Helper;
use crate::modules::probe_modules::topology_probe::topo_mod_v4::TopoModV4;
use crate::modules::target_iterators::CycleIpv4Pattern;
use crate::SYS;
use crate::tools::blocker::ipv4_blocker::BlackWhiteListV4;

mod new;
mod execute;
mod tools;

pub struct Topo4 {
    pub base_conf:Arc<BaseConf>,
    pub sender_conf:Arc<SenderBaseConf>,
    pub receiver_conf:Arc<ReceiverBaseConf>,

    // ipv4 拓扑探测模块
    pub probe:Arc<TopoModV4>,
    // ipv4 辅助拓扑探测模块(可选)
    pub sub_probe:Option<Arc<TopoModV4>>,

    pub ip_bits_num:u32,
    pub base_ip_val:u32,
    pub mask:u32,
    pub parts:Vec<(u32, u32)>,

    pub max_ttl:u8,
    
    pub tar_iter:CycleIpv4Pattern,

    pub blocker:BlackWhiteListV4,
}


impl Helper for Topo4 {
    fn print_help() -> String {

        SYS.get_info("help", "Topo4")
    }
}

