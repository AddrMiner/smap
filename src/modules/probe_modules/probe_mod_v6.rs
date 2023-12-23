


use std::process::exit;
use std::sync::Arc;
use log::error;
use pcap::PacketHeader;
use crate::core::conf::modules_config::ModuleConf;
use crate::SYS;
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;
use crate::tools::net_handle::packet::v6::packet_v6_u128::Ipv6PacketU128;

pub use crate::modules::probe_modules::v6::{IcmpEchoV6, TcpSynScanV6, TcpSynAckScanV6, TcpSynOptV6, UdpScanV6};

pub const PROBE_MODS_V6: [&str; 5] = ["icmp_v6", "tcp_syn_scan_v6", "tcp_syn_ack_scan_v6", "tcp_syn_opt_v6", "udp_scan_v6"];

impl ProbeModV6 {
    pub fn new(name: &str, conf:ModuleConf, tar_ports:&Vec<u16>, seed:u64, fields:&Vec<String>) -> ProbeModV6 {   // 传递出去一个实现了输出模块方法的 struct

        if !PROBE_MODS_V6.contains(&name) {   // 激活检查
            error!("{}", SYS.get_info("err", "v6_probe_mod_not_exist"));
            exit(1)
        }

        match name {        // 各类模块的构造方法

            "icmp_v6" => IcmpEchoV6::new(tar_ports, fields),

            "tcp_syn_scan_v6" => TcpSynScanV6::new(fields),
            "tcp_syn_ack_scan_v6" => TcpSynAckScanV6::new(fields),
            "tcp_syn_opt_v6" => TcpSynOptV6::new(conf, seed, fields),

            "udp_scan_v6" => UdpScanV6::new(conf, seed, fields),

            _ => {
                error!("{}", SYS.get_info("err", "v6_probe_mod_not_exist"));
                exit(1)
            }
        }
    }


    pub fn init(p:Arc<ProbeModV6>, sports:Vec<u16>) -> Box<dyn ProbeMethodV6> {

        let name = p.name;

        match name {        // 各类模块的构造方法

            "icmp_v6" => Box::new(IcmpEchoV6::init(p)),

            "tcp_syn_scan_v6" => Box::new(TcpSynScanV6::init(p, sports)),
            "tcp_syn_ack_scan_v6" => Box::new(TcpSynAckScanV6::init(p, sports)),
            "tcp_syn_opt_v6" => Box::new(TcpSynOptV6::init(p, sports)),

            "udp_scan_v6" => Box::new(UdpScanV6::init(p, sports)),


            _ => {
                error!("{}", SYS.get_info("err", "v6_probe_mod_not_exist"));
                exit(1)
            }
        }


    }
}


pub trait ProbeMethodV6 {


    fn thread_initialize_v6(&mut self, local_mac:&MacAddress, gateway_mac:&MacAddress);


    fn make_packet_v6(&self, source_ip:u128, dest_ip:u128, dest_port:u16, hop_limit:Option<u8>, aes_rand:&AesRand) -> Vec<u8>;

    fn is_successful(&self, data_link_header:&[u8], ipv6_header:&Ipv6PacketU128, net_layer_data:&[u8], aes_rand:&AesRand) -> bool;


    /// 验证ipv6数据包
    /// 注意:接收到的网络层数据包含 扩展首部
    fn validate_packet_v6(&self, data_link_header:&[u8], ipv6_header:&Ipv6PacketU128, net_layer_data:&[u8], aes_rand:&AesRand) -> (bool, u16, Option<u128>);


    /// 打印出首部字段
    fn print_header(&self) -> Vec<String>;

    /// 注意:接收到的网络层数据包含 扩展首部
    fn process_packet_v6(&self, header:&PacketHeader, data_link_header:&[u8],
                         ipv6_header:&Ipv6PacketU128, net_layer_data:&[u8], inner_ip:Option<u128>) -> (bool, Vec<String>);

}


pub struct ProbeModV6 {

    pub name:&'static str,

    pub max_packet_length_v6:usize,
    pub snap_len_v6:usize,
    pub filter_v6:String,

    pub use_tar_ports:bool,

    pub option:Vec<u8>,
    pub payload:Vec<u8>,

    pub fields:Vec<String>,
    pub conf:Option<ModuleConf>,
}