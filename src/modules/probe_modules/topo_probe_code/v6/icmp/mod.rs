use std::sync::Arc;
use crate::core::conf::modules_config::ModuleConf;
use crate::modules::probe_modules::topo_probe_code::topo_mod_v6::{CodeTopoProbeMethodV6, CodeTopoProbeModV6};

mod method;



pub struct CodeTopoIcmpV6 {
    base_buf: Vec<u8>,

    // 总长度
    total_len:usize,

    // 网络层长度
    net_layer_data_len:u16,
}


impl CodeTopoIcmpV6 {


    pub fn new(conf:ModuleConf) -> CodeTopoProbeModV6 {

        let payload_len:usize = conf.get_conf(&"payload_len".to_string());

        CodeTopoProbeModV6 {
            name: "code_topo_icmp_v6",

            max_packet_length_v6: 59 + payload_len,    // 以太网首部(14字节) + ipv6报头(40字节) + icmp报头(5字节) + 编码负载 = 59 +
            snap_len_v6: 110 + payload_len,             // 以太网首部(14字节) + ipv6报头(40字节) + icmp_v6首部(8个字节) + 内部的ipv6首部(40字节) + 内部icmp_v6首部(8个字节) = 110 +
            filter_v6: "icmp6 && (ip6[40] == 1 || ip6[40] == 3)".to_string(),

            code_len: payload_len as u16,
            conf: None,
        }
    }


    pub fn init(p:Arc<CodeTopoProbeModV6>) -> impl CodeTopoProbeMethodV6 {
        CodeTopoIcmpV6 {
            base_buf: Vec::with_capacity(22),
            total_len: 59 + (p.code_len as usize),                  // 以太网首部(14字节) + ipv6报头(40字节) + icmp报头(5字节) + 编码负载 = 59 +
            net_layer_data_len: 5 + p.code_len,                     // icmp_v6首部(5字节) + 编码
        }
    }

}