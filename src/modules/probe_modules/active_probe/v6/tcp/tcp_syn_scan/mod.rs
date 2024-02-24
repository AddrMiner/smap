
mod method;

use std::sync::Arc;
use crate::modes::Helper;
use crate::modules::probe_modules::probe_mod_v6::{ProbeMethodV6, ProbeModV6};
use crate::SYS;
use crate::tools::net_handle::packet::tcp::fields::TcpFields;


pub struct TcpSynScanV6 {

    base_buf:Vec<u8>,
    tcp_header_after_seq:Vec<u8>,
    max_len:usize,

    sports:Vec<u16>,
    sports_len:usize,
    print_ipv6_packet:bool,
    fields_flag:TcpFields,
}

impl TcpSynScanV6 {

    pub fn new(fields:&Vec<String>) -> ProbeModV6 {

        ProbeModV6 {
            name: "tcp_syn_scan_v6",
            max_packet_length_v6: 74,       // 以太网报头(14字节) + ipv6报头(40字节) + tcp报头(20字节) = 74
            snap_len_v6: 116,
            filter_v6: "ip6 proto 6 && (ip6[53] & 4 != 0 || ip6[53] == 18)".to_string(),

            use_tar_ports: true,

            option: vec![],
            payload: vec![],

            fields: fields.clone(),
            conf: None,
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

        TcpSynScanV6 {
            // 以太网头 14字节, 没有地址的ipv6首部 8字节       14 + 8 = 22
            base_buf: Vec::with_capacity(22),

            // tcp 首部, 序列号以后的部分    12 字节
            tcp_header_after_seq: Vec::with_capacity(12),

            max_len: p.max_packet_length_v6,

            sports_len: sports.len(),
            sports,
            fields_flag,
            print_ipv6_packet,
        }
    }

}

impl Helper for TcpSynScanV6 {
    fn print_help() -> String {
        SYS.get_info("help","TcpSynScanV6")
    }
}