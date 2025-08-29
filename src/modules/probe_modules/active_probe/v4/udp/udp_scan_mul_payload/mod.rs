mod method;

use std::process::exit;
use std::sync::Arc;
use ahash::AHashMap;
use log::error;
use crate::core::conf::modules_config::ModuleConf;
use crate::modules::probe_modules::probe_mod_v4::{ProbeMethodV4, ProbeModV4};
use crate::modules::probe_modules::tools::payload::parse_payload_from_file2;
use crate::{parse_custom_args, SYS};
use crate::modes::Helper;
use crate::tools::file::get_path::get_current_path;
use crate::tools::net_handle::packet::udp::fields::UdpFields;


pub struct UdpScanMulPayloadV4 {

    base_buf:Vec<u8>,

    not_check_sport:bool,

    sports:Vec<u16>,
    sports_len:usize,

    port_payloads:AHashMap<u16, Vec<Vec<u8>>>,

    fields_flag: UdpFields,
}

impl UdpScanMulPayloadV4 {

    pub fn new(mod_conf:ModuleConf, _seed:u64, fields:&Vec<String>) -> ProbeModV4 {

        // 得到 当前模块的 payload文件路径
        let payload_path:String = mod_conf.get_conf_or_from_sys(&"udp_mul_payload_path".to_string());
        let payload_path = get_current_path(&payload_path);

        // 解析所有 payload，并得到最大payload长度
        let (_, max_payload_len) = parse_payload_from_file2(payload_path, 0);

        ProbeModV4 {
            name: "udp_scan_mul_payload_v4",
            max_packet_length_v4: 42 + max_payload_len,   // 以太网头(14字节) + ipv4首部(20字节) + udp首部(8字节) + 载荷 =  42 + 载荷
            snap_len_v4: 1500,
            filter_v4: "udp || icmp".to_string(),

            use_tar_ports: true,

            option: vec![],
            payload: vec![],
            fields: fields.clone(),
            conf: Some(mod_conf),
        }
    }

    pub fn init(p:Arc<ProbeModV4>, sports:Vec<u16>) -> impl ProbeMethodV4 {

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

        UdpScanMulPayloadV4 {
            // 以太网头 14字节, 没有地址的ipv4首部 12字节       14 + 12 = 26
            base_buf: Vec::with_capacity(26),

            sports_len: sports.len(),
            sports,

            fields_flag: UdpFields::new(&p.fields),

            // 注意: 这里应改为 由模块配置传入的参数
            not_check_sport,
            port_payloads,
        }
    }

}





impl Helper for UdpScanMulPayloadV4 {
    fn print_help() -> String {
        SYS.get_info("help","UdpScanMulPayloadV4")
    }
}
