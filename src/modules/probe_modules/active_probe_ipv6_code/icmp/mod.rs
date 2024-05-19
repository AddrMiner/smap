use std::sync::Arc;
use crate::core::conf::modules_config::ModuleConf;
use crate::modes::Helper;
use crate::modules::probe_modules::active_probe_ipv6_code::{CodeProbeMethodV6, CodeProbeModV6};
use crate::SYS;

mod method;

pub struct CodeIcmpEchoV6 {
    
    base_buf:Vec<u8>,

    net_layer_data_len:u16,
    total_len:usize,
}



impl CodeIcmpEchoV6 {
    
    
    pub fn new(conf:ModuleConf) -> CodeProbeModV6 {
        
        let payload_len:usize = conf.get_conf(&"payload_len".to_string());
        
        CodeProbeModV6 {
            name: "code_icmp_v6",
            
            max_packet_length_v6: 66 + payload_len,       // 以太网首部(14字节) + ipv6报头(40字节) + icmp报头(8字节) + icmp验证数据(4字节) + 编码负载 = 66 + 
            snap_len_v6: 76 + payload_len,                // 以太网首部(14字节) + ipv6报头(40字节) + icmp报头(8字节) + icmp验证数据(4字节) + 编码负载 = 66 +
            filter_v6: "icmp6 && ip6[40] == 129".to_string(),
            code_len: payload_len as u16,
            conf: None,
        }
        
    }

    pub fn init(p:Arc<CodeProbeModV6>) -> impl CodeProbeMethodV6 { 
        CodeIcmpEchoV6 {
            base_buf: Vec::with_capacity(22),
            net_layer_data_len: 12 + p.code_len,              // icmp_v6首部(8字节) + 4字节验证数据 + 编码(负载长度)
            total_len: 66 + (p.code_len as usize),      // 以太网首部(14字节) + ipv6报头(40字节) + icmp报头(8字节) + icmp验证数据(4字节) + 编码负载 = 66 + 
        }
    }
}

impl Helper for CodeIcmpEchoV6 {
    fn print_help() -> String {
        SYS.get_info("help", "CodeIcmpEchoV6")
    }
}