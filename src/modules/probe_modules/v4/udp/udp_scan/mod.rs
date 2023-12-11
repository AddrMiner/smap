mod method;


use std::process::exit;
use std::sync::Arc;
use log::error;
use crate::core::conf::modules_config::ModuleConf;
use crate::modes::Helper;
use crate::modules::probe_modules::probe_mod_v4::{ProbeMethodV4, ProbeModV4};
use crate::modules::probe_modules::tools::payload::get_payload;
use crate::SYS;
use crate::tools::net_handle::packet::udp::fields::UdpFields;


pub struct UdpScanV4 {

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

impl UdpScanV4 {

    pub fn new(mod_conf:ModuleConf, seed:u64, fields:&Vec<String>) -> ProbeModV4 {

        let payload = get_payload(mod_conf.get_info(&"payload".to_string()),
                                  SYS.get_info("conf", "default_payload_file"),
                                  seed, 1, 508);

        ProbeModV4 {
            name: "udp_scan_v4",
            max_packet_length_v4: 42 + payload.len(),   // 以太网头(14字节) + ipv4首部(20字节) + udp首部(8字节) + 载荷 =  42 + 载荷
            snap_len_v4: 1500,
            filter_v4: "udp || icmp".to_string(),

            option: vec![],
            payload,
            fields: fields.clone(),
            conf: Some(mod_conf),
        }
    }

    pub fn init(p:Arc<ProbeModV4>, sports:Vec<u16>) -> impl ProbeMethodV4 {

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

        UdpScanV4 {
            // 以太网头 14字节, 没有地址的ipv4首部 12字节       14 + 12 = 26
            base_buf: Vec::with_capacity(26),
            max_len: p.max_packet_length_v4,

            udp_payload: p.payload.clone(),

            udp_len: udp_len_u16 as u32,

            udp_len_zero_check_sum_bytes: [udp_len_bytes[0], udp_len_bytes[1], 0, 0],

            sports: sports.clone(),
            sports_len: sports.len(),
            fields_flag: UdpFields::new(&p.fields),

            // 注意: 这里应改为 由模块配置传入的参数
            not_check_sport,
        }
    }

}

impl Helper for UdpScanV4 {
    fn print_help() -> String {
        SYS.get_info("help","UdpScanV4")
    }
}