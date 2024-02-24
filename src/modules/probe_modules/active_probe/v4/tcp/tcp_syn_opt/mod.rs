use std::sync::Arc;
use crate::core::conf::modules_config::ModuleConf;
use crate::modes::Helper;
use crate::modules::probe_modules::probe_mod_v4::{ProbeMethodV4, ProbeModV4};
use crate::modules::probe_modules::tools::payload::get_payload;
use crate::SYS;
use crate::tools::file::get_path::get_current_path;
use crate::tools::net_handle::packet::tcp::opt::opt_fields::TcpOptFields;

mod method;


pub struct TcpSynOptV4 {

    base_buf:Vec<u8>,
    max_len:usize,
    tcp_header_after_seq:Vec<u8>,

    opt_payload:Vec<u8>,

    tcp_len:u32,

    sports:Vec<u16>,
    sports_len:usize,
    fields_flag:TcpOptFields,
}

impl TcpSynOptV4 {

    pub fn new(mod_conf:ModuleConf, seed:u64, fields:&Vec<String>) -> ProbeModV4 {

        // 得到 payload文件路径
        let payload_path = get_current_path(&SYS.get_info("conf", "default_payload_file"));

        let mut opt_payload = get_payload(mod_conf.get_info(&"payload".to_string()),
                                          payload_path, seed, 1, 40);

        // 将负载长度填充为 4 的字节倍数
        let mut fill_bytes_len = 4 - (opt_payload.len() % 4);
        if fill_bytes_len == 4 { fill_bytes_len = 0; }
        opt_payload.extend(vec![0; fill_bytes_len]);


        ProbeModV4 {
            name: "tcp_syn_opt_v4",
            max_packet_length_v4: 54 + opt_payload.len(),                       // 以太网头(14字节) + ipv4报头(20字节) + tcp基本首部(20字节) + tcp选项字段 = 54字节 +
            snap_len_v4: 136,                                                   // 以太网头(14字节) + ipv4报头(20字节) + tcp基本首部(20字节) + tcp选项字段(40字节) = 94
            filter_v4: "tcp && tcp[13] & 4 != 0 || tcp[13] == 18".to_string(),

            use_tar_ports: true,

            option: opt_payload,
            payload: vec![],

            fields: fields.clone(),
            conf: None,
        }
    }

    pub fn init(p:Arc<ProbeModV4>, sports:Vec<u16>) -> impl ProbeMethodV4 {

        let tcp_opt_payload_len = p.option.len();

        // tcp 长度 = tcp基本首部(20字节) + 负载长度
        let tcp_len_u16 = 20 + (tcp_opt_payload_len as u16);


        TcpSynOptV4 {
            // 以太网头 14字节, 没有地址的ipv4首部 12字节       14 + 12 = 26
            base_buf: Vec::with_capacity(26),

            // tcp 首部, 序列号以后的部分    12 字节
            tcp_header_after_seq: Vec::with_capacity(12),
            max_len: p.max_packet_length_v4,

            opt_payload: p.option.clone(),
            tcp_len: tcp_len_u16 as u32,

            sports_len: sports.len(),
            sports,
            fields_flag: TcpOptFields::new(&p.fields),
        }
    }

}

impl Helper for TcpSynOptV4 {
    fn print_help() -> String {
        SYS.get_info("help","TcpSynOptV4")
    }
}





