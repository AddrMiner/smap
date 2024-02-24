mod new;
mod execute;


use std::sync::Arc;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::modes::{Helper};
use crate::modules::probe_modules::probe_mod_v4::ProbeModV4;
use crate::modules::target_iterators::TargetFileReader;
use crate::SYS;
use crate::tools::blocker::ipv4_blocker::BlackWhiteListV4;



pub struct V4FileReader {
    pub base_conf:Arc<BaseConf>,
    pub target_iter:TargetFileReader,
    pub sender_conf:Arc<SenderBaseConf>,
    pub receiver_conf:Arc<ReceiverBaseConf>,

    pub tar_num:Option<u64>,

    pub probe:Arc<ProbeModV4>,
    pub tar_ports:Vec<u16>,

    pub assigned_target_range:Vec<(u64, u64, u64)>,

    pub ttl:Option<u8>,

    pub blocker:BlackWhiteListV4,
}



impl  Helper  for V4FileReader {
    fn print_help() -> String {

        SYS.get_info("help", "V4FileReader")
    }
}