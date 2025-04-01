use std::sync::Arc;
use crate::modes::Helper;
use crate::modules::probe_modules::active_probe_ipv6_code::{CodeProbeMethodV6, CodeProbeModV6};
use crate::SYS;

mod method;



pub struct CodeTcpSynScanV6 {

    base_buf:Vec<u8>,
    tcp_header_after_seq:Vec<u8>,
    max_len:usize,

    sports:Vec<u16>,
    sports_len:usize,
}


impl CodeTcpSynScanV6 {

    pub fn new() -> CodeProbeModV6 {

        CodeProbeModV6 {
            name: "code_tcp_syn_scan_v6",
            max_packet_length_v6: 74,       // 以太网报头(14字节) + ipv6报头(40字节) + tcp报头(20字节) = 74
            snap_len_v6: 116,
            filter_v6: "ip6 proto 6 && (ip6[53] & 4 != 0 || ip6[53] == 18)".to_string(),

            code_len: 4,
            conf: None,
        }
    }

    pub fn init(p:Arc<CodeProbeModV6>, sports:Vec<u16>) -> impl CodeProbeMethodV6 {
        CodeTcpSynScanV6 {
            // 以太网头 14字节, 没有地址的ipv6首部 8字节       14 + 8 = 22
            base_buf: Vec::with_capacity(22),
            // tcp 首部, 序列号以后的部分    12 字节
            tcp_header_after_seq: Vec::with_capacity(12),

            max_len: p.max_packet_length_v6,
            sports_len: sports.len(),
            sports,
        }
    }
    
}

impl Helper for CodeTcpSynScanV6 {
    fn print_help() -> String {
        SYS.get_info("help", "CodeTcpSynScanV6")
    }
}
