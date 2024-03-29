use std::sync::Arc;
use crate::core::conf::modules_config::ModuleConf;
use crate::modes::Helper;
use crate::modules::probe_modules::topology_probe::topo_mod_v6::{TopoMethodV6, TopoModV6};
use crate::{cal_output_len, parse_custom_args, SYS};

mod method;


pub struct TopoTcpV6 {

    // 以太网首部14字节 + 不连地址的ipv6首部字段8字节
    base_buf:Vec<u8>,
    // tcp首部序列号之后的部分, 注意包含check_sum且check_sum为0    12字节
    tcp_header_after_seq:Vec<u8>,

    default_dest_port:u16,
    tcp_sports:Vec<u16>,
    tcp_sports_len:usize,

    use_ack:bool,
    use_time_encoding:bool,
    allow_tar_network_respond:bool,

    output_len:usize,
    print_default_ttl:bool,
}



impl TopoTcpV6 {

    pub fn new(mod_conf:ModuleConf) -> TopoModV6 {

        TopoModV6 {
            name: "topo_tcp_v6",

            max_packet_length_v6: 82,   // 以太网首部(14字节) + ipv6首部(40字节) + tcp首部(20字节) + 负载(8字节) = 82
            snap_len_v6: 140,           // 14(以太网首部) + 40(ipv6首部) + 8(外层icmp首部) + 40(内层ipv6首部) + 20(内层tcp首部) + 8(时间戳) = 130
            filter_v6: "icmp6 && (ip6[40] == 1 || ip6[40] == 3)".to_string(),

            conf: Some(mod_conf),
        }
    }


    pub fn init(t:Arc<TopoModV6>, sports:Vec<u16>) -> impl TopoMethodV6 {

        // 第一个参数是t指针, ()内的参数分别为 参数名称, 类型, 默认值, 从SYS中读取的错误提示的标签
        // 可传入多个参数 如: parse_custom_args!(p; (a1, bool, true, "a1_info"), (a2, u32, 0, "a2_info"));
        parse_custom_args!(t;
            (use_time_encoding, bool, true, "use_time_encoding_parse_failed"),
            (print_default_ttl, bool, false, "print_default_ttl_parse_failed"),
            (topo_tcp_use_ack, bool, false, "topo_tcp_use_ack_parse_failed"),
            (topo_dest_port, u16, SYS.get_conf("conf", "topo_dest_port"), "topo_dest_port_parse_failed"),
            (topo_allow_tar_network_respond, bool, true, "topo_allow_tar_network_respond_parse_failed")
        );

        cal_output_len!(output_len, usize, 3; use_time_encoding, print_default_ttl);

        TopoTcpV6 {
            base_buf: Vec::with_capacity(22),  // 以太网首部字段(14字节) + 不连地址的ipv6首部字段(8字节)
            tcp_header_after_seq: Vec::with_capacity(12), // tcp首部序列号之后的部分(12字节)

            default_dest_port: topo_dest_port,

            tcp_sports_len: sports.len(),
            tcp_sports: sports,

            use_ack: topo_tcp_use_ack,
            use_time_encoding,
            allow_tar_network_respond: topo_allow_tar_network_respond,
            output_len,
            print_default_ttl,
        }
    }
}


impl Helper for TopoTcpV6 {
    fn print_help() -> String {
        SYS.get_info("help", "TopoTcpV6")
    }
}

