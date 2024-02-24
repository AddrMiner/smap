

use std::process::exit;
use std::sync::Arc;
use log::error;
use pcap::PacketHeader;
use crate::core::conf::modules_config::ModuleConf;
use crate::SYS;
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;
use crate::tools::net_handle::packet::v4::packet_v4_u32::Ipv4PacketU32;

pub use crate::modules::probe_modules::v4::{IcmpEchoV4, TcpSynScanV4, TcpSynAckScanV4, TcpSynOptV4, UdpScanV4};

pub const PROBE_MODS_V4: [&str; 5] = ["icmp_v4", "tcp_syn_scan_v4", "tcp_syn_ack_scan_v4", "tcp_syn_opt_v4", "udp_scan_v4"];

impl ProbeModV4 {
    pub fn new(name: &str, conf:ModuleConf, tar_ports:&Vec<u16>, seed:u64, fields:&Vec<String>) -> ProbeModV4 {   // 传递出去一个实现了输出模块方法的 struct

        if !PROBE_MODS_V4.contains(&name) {   // 激活检查
            error!("{}", SYS.get_info("err", "v4_probe_mod_not_exist"));
            exit(1)
        }

        match name {        // 各类模块的构造方法

            "icmp_v4" => IcmpEchoV4::new(conf, tar_ports, seed, fields),

            "tcp_syn_scan_v4" => TcpSynScanV4::new(fields),
            "tcp_syn_ack_scan_v4" => TcpSynAckScanV4::new(fields),
            "tcp_syn_opt_v4" => TcpSynOptV4::new(conf, seed, fields),

            "udp_scan_v4" => UdpScanV4::new(conf, seed, fields),

            _ => {
                error!("{}", SYS.get_info("err", "v4_probe_mod_not_exist"));
                exit(1)
            }
        }
    }


    pub fn init(p:Arc<ProbeModV4>, sports:Vec<u16>) -> Box<dyn ProbeMethodV4> {

        let name = p.name;

        match name {        // 各类模块的构造方法

            "icmp_v4" => Box::new(IcmpEchoV4::init(p)),

            "tcp_syn_scan_v4" => Box::new(TcpSynScanV4::init(p, sports)),
            "tcp_syn_ack_scan_v4" => Box::new(TcpSynAckScanV4::init(p, sports)),
            "tcp_syn_opt_v4" => Box::new(TcpSynOptV4::init(p, sports)),

            "udp_scan_v4" => Box::new(UdpScanV4::init(p, sports)),

            _ => {
                error!("{}", SYS.get_info("err", "v4_probe_mod_not_exist"));
                exit(1)
            }
        }


    }
}


pub trait ProbeMethodV4 {

    fn thread_initialize_v4(&mut self, local_mac:&MacAddress, gateway_mac:&MacAddress, rand_u16:u16);

    fn make_packet_v4(&self, source_ip:u32, dest_ip:u32, dest_port:u16, ttl:Option<u8>, aes_rand:&AesRand) -> Vec<u8>;

    fn is_successful(&self, data_link_header:&[u8], ipv4_header:&Ipv4PacketU32, net_layer_data:&[u8], aes_rand:&AesRand) -> bool;

    /// 验证ipv4数据包
    fn validate_packet_v4(&self, data_link_header:&[u8], ipv4_header:&Ipv4PacketU32, net_layer_data:&[u8], aes_rand:&AesRand) -> (bool, u16, Option<u32>);

    /// 打印出首部字段
    fn print_header(&self) -> Vec<String>;

    fn process_packet_v4(&self, header:&PacketHeader, data_link_header:&[u8],
                         ipv4_header:&Ipv4PacketU32, net_layer_data:&[u8], inner_ip:Option<u32>) -> (bool, Vec<String>);

}


pub struct ProbeModV4 {

    pub name:&'static str,

    pub max_packet_length_v4:usize,
    pub snap_len_v4:usize,
    pub filter_v4:String,

    pub use_tar_ports:bool,

    pub option:Vec<u8>,
    pub payload:Vec<u8>,

    pub fields:Vec<String>,
    pub conf:Option<ModuleConf>,
}