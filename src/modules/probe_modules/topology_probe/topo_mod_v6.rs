
use std::process::exit;
use std::sync::Arc;
use log::error;
use crate::core::conf::modules_config::ModuleConf;
use crate::SYS;
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;

pub use crate::modules::probe_modules::topology_probe::v6::{TopoUdpV6, TopoIcmpV6, TopoTcpV6};

pub const TOPO_MODS_V6: [&str; 3] = ["topo_icmp_v6", "topo_udp_v6", "topo_tcp_v6"];

impl TopoModV6 {


    pub fn new(name: &str, conf:ModuleConf) -> TopoModV6 {

        if !TOPO_MODS_V6.contains(&name) { // 激活检查
            error!("{}", SYS.get_info("err", "v6_probe_mod_not_exist"));
            exit(1)
        }

        match name {

            "topo_icmp_v6" => TopoIcmpV6::new(conf),
            "topo_udp_v6"  => TopoUdpV6::new(conf),
            "topo_tcp_v6"  => TopoTcpV6::new(conf),

            _ => {
                error!("{}", SYS.get_info("err", "v6_probe_mod_not_exist"));
                exit(1)
            }
        }
    }

    
    pub fn init(t:Arc<TopoModV6>, sports:Vec<u16>) -> Box<dyn TopoMethodV6> {

        let name = t.name;

        match name {
            
            "topo_icmp_v6" => Box::new(TopoIcmpV6::init(t)),
            "topo_udp_v6" => Box::new(TopoUdpV6::init(t, sports)),
            "topo_tcp_v6" => Box::new(TopoTcpV6::init(t, sports)),

            _ => {
                error!("{}", SYS.get_info("err", "v6_probe_mod_not_exist"));
                exit(1)
            }
        }
    }
}




pub trait TopoMethodV6 {

    fn thread_initialize_v6(&mut self, local_mac:&MacAddress, gateway_mac:&MacAddress);

    fn make_packet_v6(&self, source_ip:u128, dest_ip:u128, dest_port_offset:Option<u16>, hop_limit:u8, aes_rand:&AesRand) -> Vec<u8>;

    fn parse_packet_v6(&self, ts:&libc::timeval, ipv6_header:&[u8], net_layer_data:&[u8], aes_rand:&AesRand) -> Option<TopoResultV6>;

    /// 打印出首部字段
    fn print_header(&self) -> Vec<String>;

    fn print_record(&self, res:&TopoResultV6, net_layer_header_and_data:&[u8]) -> Vec<String>;

    fn print_silent_record(&self, dest_ip:u128, distance:u8) -> Vec<String>;


}


pub struct TopoModV6 {

    pub name:&'static str,

    pub max_packet_length_v6:usize,
    pub snap_len_v6:usize,
    pub filter_v6:String,

    pub conf:Option<ModuleConf>,
}


pub struct TopoResultV6 {
    pub dest_ip:u128,    // 发送时的 目的地址
    pub responder:u128,  // 响应的 源地址
    pub distance:u8,    // 从 源点 出发的跳数

    pub from_destination:bool, // 是否是来自 目的地址 的响应

    pub rtt:u64         // 往返时延 以毫秒为单位
}