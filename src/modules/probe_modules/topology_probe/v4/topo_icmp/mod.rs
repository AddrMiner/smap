use std::sync::Arc;
use crate::core::conf::modules_config::ModuleConf;
use crate::modes::Helper;
use crate::modules::probe_modules::topology_probe::topo_mod_v4::{TopoMethodV4, TopoModV4};
use crate::{parse_custom_args, SYS};

mod method;


pub struct TopoIcmpV4 {
    // 以太网帧首部 + ipv4首部 id字段 之前的四个字节
    base_buf:Vec<u8>,
    // ipv4 的 id字段之后 到 地址 之前的 6 字节
    ipv4_header_base_buf_2:Vec<u8>,

    allow_tar_network_respond:bool,

    // 是否使用 时间戳 进行编码
    use_time_encoding:bool,
    // 打印响应主机的 默认ttl
    print_default_ttl:bool,
    // 输出向量大小
    output_len:usize,
}

impl TopoIcmpV4 {
    
    pub fn new(mod_conf:ModuleConf) -> TopoModV4 {
        
        TopoModV4 {
            name: "topo_icmp_v4",
            // 以太网首部(14字节) + ipv4首部(20字节) + icmp首部(8字节)  = 42
            max_packet_length_v4: 42,
            snap_len_v4: 96,
            filter_v4: "icmp".to_string(),
            conf: Some(mod_conf),
        }
    }
    
    pub fn init(t:Arc<TopoModV4>) -> impl TopoMethodV4 {

        parse_custom_args!(t;
            (use_time_encoding, bool, true, "use_time_encoding_parse_failed"),
            (print_default_ttl, bool, false, "print_default_ttl_parse_failed"),
            (topo_allow_tar_network_respond, bool, true, "topo_allow_tar_network_respond_parse_failed")
        );


        let mut output_len = 3;
        if use_time_encoding { output_len += 1; }
        if print_default_ttl { output_len += 1; }
        
        TopoIcmpV4 {
            base_buf: Vec::with_capacity(18),               // 以太网首部 (14字节) + ipv4首部 id字段 之前的 4字节
            ipv4_header_base_buf_2: Vec::with_capacity(6),  // ipv4 的 id字段之后 到 地址 之前的 6 字节
            allow_tar_network_respond:topo_allow_tar_network_respond,

            use_time_encoding,
            print_default_ttl,
            output_len,
        }
        
    }
    
}

impl Helper for TopoIcmpV4 {
    fn print_help() -> String {
        SYS.get_info("help", "TopoIcmpV4")
    }
}