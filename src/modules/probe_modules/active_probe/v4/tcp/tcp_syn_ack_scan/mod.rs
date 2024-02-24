

mod method;

use std::sync::Arc;
use crate::modes::Helper;
use crate::modules::probe_modules::probe_mod_v4::{ProbeMethodV4, ProbeModV4};
use crate::SYS;
use crate::tools::net_handle::packet::tcp::fields::TcpFields;


pub struct TcpSynAckScanV4 {

    base_buf:Vec<u8>,
    tcp_header_after_ack:Vec<u8>,
    max_len:usize,

    sports:Vec<u16>,
    sports_len:usize,
    fields_flag:TcpFields,
}

impl TcpSynAckScanV4 {

    pub fn new(fields:&Vec<String>) -> ProbeModV4 {

        ProbeModV4 {
            name: "tcp_syn_ack_scan_v4",
            max_packet_length_v4: 58,               // 以太网头(14字节) + ipv4报头(20字节) + tcp基本首部(20字节) + mss扩展首部(4字节) = 58字节
            snap_len_v4: 114,                        // 以太网头(14字节) + 外层ipv4报头(20字节) + ipv4可选字段(40字节) + 外层icmp报头(8字节) + 内层ipv4报头(20字节) + mss(4字节) + 原始数据包前8字节(8字节) = 114
            filter_v4: "(tcp && tcp[13] & 4 != 0 || tcp[13] == 18) || icmp".to_string(),

            use_tar_ports: true,

            option: vec![],
            payload: vec![],

            fields: fields.clone(),
            conf:None,
        }
    }

    pub fn init(p:Arc<ProbeModV4>, sports:Vec<u16>) -> impl ProbeMethodV4 {

        TcpSynAckScanV4 {
            // 以太网头 14字节, 没有地址的ipv4首部 12字节       14 + 12 = 26
            base_buf: Vec::with_capacity(26),

            // tcp 首部, 确认序号以后的部分(包含mss字段)    8 字节 + 4 字节 = 12 字节
            tcp_header_after_ack: Vec::with_capacity(12),

            max_len: p.max_packet_length_v4,

            sports_len: sports.len(),
            sports,
            fields_flag: TcpFields::new(&p.fields),
        }
    }

}

impl Helper for TcpSynAckScanV4 {
    fn print_help() -> String {
        SYS.get_info("help","TcpSynAckScanV4")
    }
}