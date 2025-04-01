use std::sync::Arc;
use crate::core::conf::modules_config::ModuleConf;
use crate::modules::probe_modules::probe_mod_v6::{ProbeMethodV6, ProbeModV6};
use crate::modules::probe_modules::tools::payload::get_payload;
use crate::SYS;
use crate::modes::Helper;
use crate::tools::file::get_path::get_current_path;
use crate::tools::net_handle::packet::tcp::fields::TcpFields;

mod method;




pub struct TcpSynPayloadScan {
    
    base_buf:Vec<u8>,
    tcp_header_after_seq:Vec<u8>,
    max_len:usize,

    // 选项字段负载
    opt_payload:Vec<u8>,
    // 应用层载荷
    payload:Vec<u8>,

    tcp_len:u32,

    sports:Vec<u16>,
    sports_len:usize,

    print_ipv6_packet:bool,
    print_data:bool,
    fields_flag:TcpFields,
}



impl TcpSynPayloadScan {


    pub fn new(mod_conf:ModuleConf, seed:u64, fields:&Vec<String>) -> ProbeModV6 {

        // 得到 payload文件路径
        let payload_path = get_current_path(&SYS.get_info("conf", "default_payload_file"));

        // 将负载长度填充为 4 的字节倍数
        let mut opt_payload = get_payload(mod_conf.get_info(&"opt_payload".to_string()),
                                          payload_path.clone(), seed, 0, 40);
        let mut fill_bytes_len = 4 - (opt_payload.len() % 4);
        if fill_bytes_len == 4 { fill_bytes_len = 0; }
        opt_payload.extend(vec![0; fill_bytes_len]);

        // 应用层载荷
        let payload = get_payload(mod_conf.get_info(&"payload".to_string()),
                                  payload_path, seed, 0, 500);
        

        ProbeModV6 {
            name: "tcp_syn_payload_scan_v6",
            max_packet_length_v6: 74 + opt_payload.len() + payload.len(),        //  以太网头(14字节) + ipv6报头(40字节) + tcp基本首部(20字节) + 负载长度 = 74字节 +
            snap_len_v6: 1500,
            filter_v6: "ip6 proto 6 || icmp6".to_string(),

            use_tar_ports: true,

            option: opt_payload,
            payload,

            fields: fields.clone(),
            conf: Some(mod_conf),
        }
    }


    pub fn init(p:Arc<ProbeModV6>, sports:Vec<u16>) -> impl ProbeMethodV6 {

        let mut fields_flag = TcpFields::new(&p.fields);

        let print_ipv6_packet;
        if p.fields.contains(&"ipv6_packet".to_string()) {
            fields_flag.len += 7;
            print_ipv6_packet = true;
        } else {
            print_ipv6_packet = false;
        }

        let print_data:bool;
        if let Some(a) = p.conf.clone() {
            // 如果有自定义参数
            print_data = a.get_conf_or_from_sys(&"print_data".to_string());
        } else { 
            print_data = true;
        }
        if print_data { fields_flag.len += 1; }

        // tcp 长度 = tcp基本首部(20字节) + 选项长度 + 负载长度
        let tcp_len_u16 = 20 + (p.option.len() as u16) + (p.payload.len() as u16);
        

        TcpSynPayloadScan {
            // 以太网头 14字节, 没有地址的ipv6首部 8字节       14 + 8 = 22
            base_buf: Vec::with_capacity(22),

            // tcp 首部, 序列号以后的部分    12 字节
            tcp_header_after_seq: Vec::with_capacity(12),
            
            max_len: p.max_packet_length_v6,
            
            opt_payload: p.option.clone(),
            payload: p.payload.clone(),
            
            tcp_len: tcp_len_u16 as u32,

            sports_len: sports.len(),
            sports,
            
            print_ipv6_packet,
            print_data,
            fields_flag,
        }
    }
}

impl Helper for TcpSynPayloadScan {
    fn print_help() -> String {
        SYS.get_info("help","TcpSynPayloadScanV6")
    }
}