mod method;

use std::sync::Arc;
use crate::modes::Helper;
use crate::modules::probe_modules::probe_mod_v4::{ProbeMethodV4, ProbeModV4};
use crate::SYS;
use crate::tools::net_handle::packet::tcp::fields::TcpFields;

pub struct TcpSynScanV4 {

    base_buf:Vec<u8>,
    tcp_header_after_seq:Vec<u8>,
    max_len:usize,

    sports:Vec<u16>,
    sports_len:usize,

    print_ipv4_packet:bool,
    fields_flag:TcpFields,
}

impl TcpSynScanV4 {

    pub fn new(fields:&Vec<String>) -> ProbeModV4 {

        ProbeModV4 {
            name: "tcp_syn_scan_v4",
            max_packet_length_v4: 58,           // 以太网头(14字节) + ipv4报头(20字节) + tcp基本首部(20字节) + mss扩展首部(4字节) = 58字节
            snap_len_v4: 96,
            filter_v4: "(tcp && tcp[13] & 4 != 0 || tcp[13] == 18) || icmp".to_string(),

            use_tar_ports: true,

            option: vec![],
            payload: vec![],

            fields: fields.clone(),
            conf: None,
        }
    }

    pub fn init(p:Arc<ProbeModV4>, sports:Vec<u16>) -> impl ProbeMethodV4 {

        let mut fields_flag = TcpFields::new(&p.fields);

        let print_ipv4_packet;
        if p.fields.contains(&"ipv4_packet".to_string()) {
            fields_flag.len += 13;
            print_ipv4_packet = true;
        } else {
            print_ipv4_packet = false;
        }
        

        TcpSynScanV4 {
            // 以太网头 14字节, 没有地址的ipv4首部 12字节       14 + 12 = 26
            base_buf: Vec::with_capacity(26),

            // tcp 首部, 序列号以后的部分(包含mss字段)    12 字节 + 4 字节 = 16 字节
            tcp_header_after_seq: Vec::with_capacity(16),

            max_len: p.max_packet_length_v4,

            sports_len: sports.len(),
            sports,

            fields_flag,
            print_ipv4_packet,
        }
    }
}


impl Helper for TcpSynScanV4 {
    fn print_help() -> String {
        SYS.get_info("help", "TcpSynScanV4")
    }
}