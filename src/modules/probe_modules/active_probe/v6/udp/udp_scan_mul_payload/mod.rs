mod method;

use std::process::exit;
use std::sync::Arc;
use ahash::AHashMap;
use log::error;
use crate::core::conf::modules_config::ModuleConf;
use crate::modes::Helper;
use crate::modules::probe_modules::probe_mod_v6::{ProbeMethodV6, ProbeModV6};
use crate::modules::probe_modules::tools::payload::parse_payload_from_file2;
use crate::{parse_custom_args, SYS};
use crate::tools::file::get_path::get_current_path;
use crate::tools::net_handle::packet::udp::fields::UdpFields;

pub struct UdpScanMulPayloadV6 {

    base_buf:Vec<u8>,

    not_check_sport:bool,

    sports:Vec<u16>,
    sports_len:usize,

    port_payloads:AHashMap<u16, Vec<Vec<u8>>>,

    fields_flag:UdpFields,

}


impl UdpScanMulPayloadV6 {

    pub fn new(mod_conf:ModuleConf, _seed:u64, fields:&Vec<String>) -> ProbeModV6 {

        // 得到 当前模块的 payload文件路径
        let payload_path:String = mod_conf.get_conf_or_from_sys(&"udp_mul_payload_path".to_string());
        let payload_path = get_current_path(&payload_path);

        // 解析所有 payload，并得到最大payload长度
        let (_, max_payload_len) = parse_payload_from_file2(payload_path, 0);


        ProbeModV6 {
            name: "udp_scan_mul_payload_v6",
            max_packet_length_v6: 62 + max_payload_len,  // 以太网头(14字节) + ipv6首部(40字节) + udp首部(8字节) + 载荷 = 62 + 载荷
            snap_len_v6: 1500,
            filter_v6: "ip6 proto 17 || icmp6".to_string(),

            use_tar_ports: true,

            option: vec![],
            payload: vec![],
            fields: fields.clone(),
            conf: Some(mod_conf),
        }
    }


    pub fn init(p:Arc<ProbeModV6>, sports:Vec<u16>) -> impl ProbeMethodV6 {

        let payload_path:String = if let Some(mod_conf) = &p.conf {
            // 得到 当前模块的 payload文件路径
            mod_conf.get_conf_or_from_sys(&"udp_mul_payload_path".to_string())
        } else {
            if let Some(payload_path_) = SYS.get_info_without_panic("conf", "udp_mul_payload_path") {
                payload_path_
            } else {
                error!("{}", SYS.get_info("err", "udp_mul_payload_path_unset"));
                exit(1)
            }
        };
        // 转换为绝对路径
        let payload_path = get_current_path(&payload_path);
        // 得到最终的payload
        let (port_payloads, _) = parse_payload_from_file2(payload_path, 0);

        // 第一个参数是p指针, ()内的参数分别为 参数名称, 类型, 默认值, 从SYS中读取的错误提示的标签
        // 可传入多个参数 如: parse_custom_args!(p; (a1, bool, true, "a1_info"), (a2, u32, 0, "a2_info"));
        parse_custom_args!(p; (not_check_sport, bool, false, "not_check_sport_parse_failed"));

        UdpScanMulPayloadV6 {
            // 以太网头 14字节, 没有地址的ipv6首部 8字节       14 + 8 = 22
            base_buf: Vec::with_capacity(22),
            not_check_sport,

            sports_len: sports.len(),
            sports,

            port_payloads,

            fields_flag: UdpFields::new(&p.fields),
        }
    }
}

impl Helper for UdpScanMulPayloadV6 {
    fn print_help() -> String {
        SYS.get_info("help","UdpScanMulPayloadV6")
    }
}