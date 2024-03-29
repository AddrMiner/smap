use std::sync::Arc;
use crate::core::conf::modules_config::ModuleConf;
use crate::modes::Helper;
use crate::modules::probe_modules::topology_probe::topo_mod_v6::{TopoMethodV6, TopoModV6};
use crate::{cal_output_len, parse_custom_args, SYS};

mod method;


pub struct TopoIcmpV6 {

    base_buf:Vec<u8>,
    allow_tar_network_respond:bool,

    // 是否使用 时间戳 进行编码
    use_time_encoding:bool,
    // 打印响应主机的 默认ttl
    print_default_ttl:bool,
    // 输出向量大小
    output_len:usize,
}


impl TopoIcmpV6 {
    
    pub fn new(mod_conf:ModuleConf) -> TopoModV6 {
        
        TopoModV6 {
            name: "topo_icmp_v6",
            
            max_packet_length_v6: 70,
            snap_len_v6: 120,                     
            filter_v6: "icmp6 && (ip6[40] == 129 || ip6[40] == 3 || ip6[40] == 1)".to_string(),
            
            conf: Some(mod_conf),
        }
    }
    
    
    pub fn init(t:Arc<TopoModV6>) -> impl TopoMethodV6 {

        parse_custom_args!(t;
            (use_time_encoding, bool, true, "use_time_encoding_parse_failed"),
            (print_default_ttl, bool, false, "print_default_ttl_parse_failed"),
            (topo_allow_tar_network_respond, bool, true, "topo_allow_tar_network_respond_parse_failed")
        );
        
        cal_output_len!(output_len, usize, 3; use_time_encoding, print_default_ttl);

        TopoIcmpV6 {
            base_buf: Vec::with_capacity(22),    // 以太网首部(14字节) + 不连地址的ipv6首部字段  8字节
            allow_tar_network_respond: topo_allow_tar_network_respond,

            use_time_encoding,
            print_default_ttl,
            output_len,
        }
    }
}

impl Helper for TopoIcmpV6 {
    fn print_help() -> String {
        SYS.get_info("help", "TopoIcmpV6")
    }
}