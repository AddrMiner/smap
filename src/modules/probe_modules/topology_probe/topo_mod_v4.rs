use std::process::exit;
use std::sync::Arc;
use log::error;
use crate::core::conf::modules_config::ModuleConf;
use crate::SYS;
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;

pub use crate::modules::probe_modules::topology_probe::v4::{TopoUdpV4, TopoIcmpV4, TopoTcpV4};

pub const TOPO_MODS_V4: [&str; 3] = ["topo_icmp_v4", "topo_udp_v4", "topo_tcp_v4"];

impl TopoModV4 {

    pub fn new(name: &str, conf:ModuleConf) -> TopoModV4 {

        if !TOPO_MODS_V4.contains(&name) { // 激活检查
            error!("{}", SYS.get_info("err", "v4_probe_mod_not_exist"));
            exit(1)
        }

        match name {

            "topo_icmp_v4" => TopoIcmpV4::new(conf),
            "topo_udp_v4"  => TopoUdpV4::new(conf),
            "topo_tcp_v4" => TopoTcpV4::new(conf),

            _ => {
                error!("{}", SYS.get_info("err", "v4_probe_mod_not_exist"));
                exit(1)
            }
        }
    }


    pub fn init(t:Arc<TopoModV4>, sports:Vec<u16>) -> Box<dyn TopoMethodV4> {

        let name = t.name;

        match name {

            "topo_icmp_v4" => Box::new(TopoIcmpV4::init(t)),
            "topo_udp_v4"  => Box::new(TopoUdpV4::init(t, sports)),
            "topo_tcp_v4"  => Box::new(TopoTcpV4::init(t, sports)),

            _ => {
                error!("{}", SYS.get_info("err", "v4_probe_mod_not_exist"));
                exit(1)
            }
        }
    }
}




pub trait TopoMethodV4 {

    fn thread_initialize_v4(&mut self, local_mac:&MacAddress, gateway_mac:&MacAddress);

    fn make_packet_v4(&self, source_ip:u32, dest_ip:u32, dest_port_offset:Option<u16>, ttl:u8, aes_rand:&AesRand) -> Vec<u8>;

    fn parse_packet_v4(&self, ts:&libc::timeval, ipv4_header:&[u8], net_layer_data:&[u8], aes_rand:&AesRand) -> Option<TopoResultV4>;

    /// 打印出首部字段
    fn print_header(&self) -> Vec<String>;

    fn print_record(&self, res:&TopoResultV4, net_layer_header_and_data:&[u8]) -> Vec<String>;
    
    fn print_silent_record(&self, dest_ip:u32, distance:u8) -> Vec<String>;


}


#[derive(Clone)]
pub struct TopoModV4 {

    pub name:&'static str,

    pub max_packet_length_v4:usize,
    pub snap_len_v4:usize,
    pub filter_v4:String,

    pub conf:Option<ModuleConf>,
}

pub struct TopoResultV4 {
    pub dest_ip:u32,    // 发送时的 目的地址
    pub responder:u32,  // 响应的 源地址
    pub distance:u8,    // 从 源点 出发的跳数

    pub from_destination:bool, // 是否是来自 目的地址 的响应

    pub rtt:u16         // 往返时延 以毫秒为单位
}