mod method;

use std::sync::Arc;
use crate::core::conf::modules_config::ModuleConf;
use crate::modes::Helper;
use crate::modules::probe_modules::probe_mod_v6::{ProbeMethodV6, ProbeModV6};
use crate::modules::probe_modules::tools::payload::get_payload;
use crate::SYS;
use crate::tools::file::get_path::get_current_path;
use crate::tools::net_handle::packet::tcp::opt::opt_fields::TcpOptFields;


pub struct TcpSynOptV6 {

    base_buf:Vec<u8>,
    max_len:usize,
    tcp_header_after_seq:Vec<u8>,

    opt_payload:Vec<u8>,

    tcp_len:u32,

    sports:Vec<u16>,
    sports_len:usize,
    fields_flag:TcpOptFields,
}

impl TcpSynOptV6 {

    pub fn new(mod_conf:ModuleConf, seed:u64, fields:&Vec<String>) -> ProbeModV6 {

        // 得到 payload文件路径
        let payload_path = get_current_path(&SYS.get_info("conf", "default_payload_file"));
        // 将负载长度填充为 4 的字节倍数
        let mut opt_payload = get_payload(mod_conf.get_info(&"payload".to_string()),
                                          payload_path, seed, 1, 40);
        let mut fill_bytes_len = 4 - (opt_payload.len() % 4);
        if fill_bytes_len == 4 { fill_bytes_len = 0; }
        opt_payload.extend(vec![0; fill_bytes_len]);


        ProbeModV6 {
            name: "tcp_syn_opt_v6",
            max_packet_length_v6: 74 + opt_payload.len(),             //  以太网头(14字节) + ipv6报头(40字节) + tcp基本首部(20字节) + tcp选项字段 = 74字节 +
            snap_len_v6: 156,                                         //  数据链路层报头(14字节) + ipv6报头(40字节) + tcp报头(20字节) + tcp选项字段最大长度(40字节) = 114
            filter_v6: "ip6 proto 6 && (ip6[53] & 4 != 0 || ip6[53] == 18)".to_string(),

            use_tar_ports: true,

            option: opt_payload,
            payload: vec![],

            fields: fields.clone(),
            conf: None,
        }
    }

    pub fn init(p:Arc<ProbeModV6>, sports:Vec<u16>) -> impl ProbeMethodV6 {

        let tcp_opt_payload_len = p.option.len();

        // tcp 长度 = tcp基本首部(20字节) + 负载长度
        let tcp_len_u16 = 20 + (tcp_opt_payload_len as u16);


        TcpSynOptV6 {
            // 以太网头 14字节, 没有地址的ipv6首部 8字节       14 + 8 = 22
            base_buf: Vec::with_capacity(22),

            // tcp 首部, 序列号以后的部分    12 字节
            tcp_header_after_seq: Vec::with_capacity(12),
            max_len: p.max_packet_length_v6,

            opt_payload: p.option.clone(),
            tcp_len: tcp_len_u16 as u32,

            sports_len: sports.len(),
            sports,
            fields_flag: TcpOptFields::new(&p.fields),
        }
    }

}

impl Helper for TcpSynOptV6 {
    fn print_help() -> String {
        SYS.get_info("help","TcpSynOptV6")
    }
}