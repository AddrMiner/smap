use std::sync::Arc;
use crate::core::conf::modules_config::ModuleConf;
use crate::modes::Helper;
use crate::modules::probe_modules::topology_probe::topo_mod_v4::{TopoMethodV4, TopoModV4};
use crate::{cal_output_len, parse_custom_args};
use crate::SYS;

mod method;



pub struct TopoTcpV4 {

    // 以太网帧首部 + ipv4首部 前4固定字节
    base_buf:Vec<u8>,
    // ipv4 的 id字段之后 到 地址 之前的 6 字节
    ipv4_header_base_buf_2:Vec<u8>,
    tcp_header_after_seq:Vec<u8>,
    
    // 是否使用 ack 探针
    use_ack:bool,
    
    // 默认目标端口(起始目标端口)
    default_dest_port:u16,
    
    // tcp 源端口向量
    tcp_sports:Vec<u16>,
    tcp_sports_len:usize,

    output_len:usize,
    allow_tar_network_respond:bool,
    use_time_encoding:bool,
    print_default_ttl:bool,
}


impl TopoTcpV4 {
    
    pub fn new(mod_conf:ModuleConf) -> TopoModV4 {
        
        TopoModV4 {
            name: "topo_tcp_v4",
            
            max_packet_length_v4: 54,           // 固定为54
            snap_len_v4: 75,                    // 以太网头(14字节) + ipv4首部(20字节) + 外层icmp(8字节) + 内层ipv4报头(20字节) + 内层tcp报头前8字节 = 70
            filter_v4: "icmp".to_string(),
            
            conf: Some(mod_conf),
        }
    }
    
    
    pub fn init(t:Arc<TopoModV4>, sports:Vec<u16>) -> impl TopoMethodV4 {
        parse_custom_args!(t;
            (use_time_encoding, bool, true, "use_time_encoding_parse_failed"),
            (print_default_ttl, bool, false, "print_default_ttl_parse_failed"),
            (topo_tcp_use_ack, bool, false, "topo_tcp_use_ack_parse_failed"),
            (topo_dest_port, u16, SYS.get_conf("conf", "topo_dest_port"), "topo_dest_port_parse_failed"),
            (topo_allow_tar_network_respond, bool, true, "topo_allow_tar_network_respond_parse_failed")
        );
        
        cal_output_len!(output_len, usize, 3; use_time_encoding, print_default_ttl);
        
        TopoTcpV4 {
            base_buf: Vec::with_capacity(18),               // 以太网首部 (14字节) + ipv4首部前4字节 (4字节) 
            ipv4_header_base_buf_2: Vec::with_capacity(6),  // ipv4 的 id字段之后 到 地址 之前的 6 字节
            tcp_header_after_seq: Vec::with_capacity(12),   // tcp首部序列号之后的部分(12字节)
            
            use_ack: topo_tcp_use_ack,
            default_dest_port: topo_dest_port,
            tcp_sports_len: sports.len(),
            tcp_sports: sports,
            
            output_len,
            allow_tar_network_respond:topo_allow_tar_network_respond,
            use_time_encoding,
            print_default_ttl,
        }
    }
    
}

impl Helper for TopoTcpV4 {
    fn print_help() -> String {
        SYS.get_info("help", "TopoTcpV4")
    }
}