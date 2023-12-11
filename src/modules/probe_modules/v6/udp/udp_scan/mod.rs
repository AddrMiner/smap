mod method;


use std::process::exit;
use std::sync::Arc;
use log::error;
use crate::core::conf::modules_config::ModuleConf;
use crate::modes::Helper;
use crate::modules::probe_modules::probe_mod_v6::{ProbeMethodV6, ProbeModV6};
use crate::modules::probe_modules::tools::payload::get_payload;
use crate::SYS;
use crate::tools::net_handle::packet::udp::fields::UdpFields;


pub struct UdpScanV6 {

    base_buf:Vec<u8>,
    max_len:usize,

    udp_payload:Vec<u8>,

    udp_len:u32,
    udp_len_zero_check_sum_bytes:[u8; 4],      // 包含 长度 和 填充为0的check_sum字段, 注意为 大端顺序

    not_check_sport:bool,

    sports:Vec<u16>,
    sports_len:usize,
    fields_flag: UdpFields,
}

impl UdpScanV6 {

    pub fn new(mod_conf:ModuleConf, seed:u64, fields:&Vec<String>) -> ProbeModV6 {

        let payload = get_payload(mod_conf.get_info(&"payload".to_string()),
                                  SYS.get_info("conf", "default_payload_file"),
                                  seed, 1, 508);

        ProbeModV6 {
            name: "udp_scan_v6",
            max_packet_length_v6: 62 + payload.len(),     // 以太网头(14字节) + ipv6首部(40字节) + udp首部(8字节) + 载荷 = 62 + 载荷
            snap_len_v6: 1500,
            filter_v6: "ip6 proto 17 || icmp6".to_string(),

            option: vec![],
            payload,
            fields: fields.clone(),
            conf: Some(mod_conf),
        }
    }

    pub fn init(p:Arc<ProbeModV6>, sports:Vec<u16>) -> impl ProbeMethodV6 {

        let udp_payload_len = p.payload.len();

        // udp 长度 = udp基本首部(8字节) + 负载长度
        let udp_len_u16 = 8 + (udp_payload_len as u16);
        let udp_len_bytes = udp_len_u16.to_be_bytes();

        let not_check_sport:bool = match p.conf.clone() {
            Some(c) => {
                match c.get_info(&"not_check_sport".to_string()) {
                    Some(val) => {
                        val.trim().parse().map_err(|_|{
                            // 解析 not_check_sport 参数失败
                            error!("{}", SYS.get_info("err", "not_check_sport_parse_failed"));
                            exit(1)
                        }).unwrap()
                    }
                    // 没有该参数, 默认为不对源端口进行检查
                    None => true,
                }
            }
            // 没有该参数, 默认为不对源端口进行检查
            None => true,
        };

        UdpScanV6 {
            // 以太网头 14字节, 没有地址的ipv6首部 8字节       14 + 8 = 22
            base_buf: Vec::with_capacity(22),
            max_len: p.max_packet_length_v6,

            udp_payload: p.payload.clone(),

            udp_len: udp_len_u16 as u32,

            udp_len_zero_check_sum_bytes: [udp_len_bytes[0], udp_len_bytes[1], 0, 0],

            not_check_sport,

            sports: sports.clone(),
            sports_len: sports.len(),
            fields_flag: UdpFields::new(&p.fields),
        }
    }

}

impl Helper for UdpScanV6 {
    fn print_help() -> String {
        SYS.get_info("help","UdpScanV6")
    }
}