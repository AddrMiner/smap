use std::sync::Arc;
use crate::core::conf::modules_config::ModuleConf;
use crate::modules::probe_modules::topology_probe::topo_mod_v6::{TopoMethodV6, TopoModV6};
use crate::{cal_output_len, parse_custom_args, SYS};
use crate::modes::Helper;
use crate::modules::probe_modules::topology_probe::tools::payload::get_topo_message;

mod method;


pub struct TopoUdpV6 {

    base_buf:Vec<u8>,

    // udp协议 目的端口
    udp_dest_port:u16,

    // udp协议 源端口向量
    udp_sports:Vec<u16>,
    udp_sports_len:usize,

    udp_payload:Vec<u8>,

    // 注意: 该设置用于 允许来自目标网络的不可达消息
    // 当用于测量网络内部结构时 必须置为 false(默认)
    // 当以网络为单位测量 互联网的整体拓扑或比较大的网络时 建议置为 true
    allow_tar_network_respond:bool,

    // 是否使用 时间戳 进行编码
    use_time_encoding:bool,
    // 打印响应主机的 默认ttl
    print_default_ttl:bool,
    // 输出向量大小
    output_len:usize,
}


impl TopoUdpV6 {
    
    pub fn new(mod_conf:ModuleConf) -> TopoModV6 {
        
        TopoModV6 {
            name: "topo_udp_v6",
            
            max_packet_length_v6: 100,          //  70 + 16(可变长度) = 86
            snap_len_v6: 150,                   //  14(以太网首部) + 40(ipv6首部) + 65 + 16(可变长度) = 135
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
            (topo_dest_port, u16, SYS.get_conf("conf", "topo_dest_port"), "topo_dest_port_parse_failed"),
            (topo_payload, String, SYS.get_conf("conf","topo_payload"), "topo_payload_parse_failed"),
            (topo_payload_allow_repeat, bool, true, "topo_payload_allow_repeat_parse_failed"),
            (topo_allow_tar_network_respond, bool, true, "topo_allow_tar_network_respond_parse_failed")
        );

        let udp_payload = get_topo_message(topo_payload, topo_payload_allow_repeat, "topo_payload_len_err", 20);

        cal_output_len!(output_len, usize, 3; use_time_encoding, print_default_ttl);
        
        TopoUdpV6 {
            base_buf: Vec::with_capacity(18),                    // 以太网首部 (14字节) + ipv6首部 有效载荷长度 字段前 (4字节)
            udp_dest_port:topo_dest_port,
            udp_sports_len: sports.len(),
            udp_sports:sports,
            udp_payload,

            allow_tar_network_respond:topo_allow_tar_network_respond,

            use_time_encoding,
            print_default_ttl,
            output_len,
        }
    }
}

impl Helper for TopoUdpV6 {
    fn print_help() -> String {
        SYS.get_info("help", "TopoUdpV6")
    }
}