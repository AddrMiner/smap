use std::process::exit;
use std::sync::Arc;
use log::error;
use crate::modes::Helper;
use crate::modules::probe_modules::topology_probe::topo_mod_v4::{TopoMethodV4, TopoModV4};
use crate::{parse_custom_args, SYS};
use crate::core::conf::modules_config::ModuleConf;

mod method;


pub struct TopoV4 {

    // 以太网帧首部 + ipv4首部 前两固定字节
    base_buf:Vec<u8>,

    // ipv4 的 id字段之后 到 地址 之前的 6 字节
    ipv4_header_base_buf_2:Vec<u8>,

    // 是否使用 时间戳 进行编码
    use_time_encoding:bool,

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
}


impl TopoV4 {

    pub fn new(mod_conf:ModuleConf) -> TopoModV4 {

        TopoModV4 {
            name: "topo_v4",

            max_packet_length_v4: 200,            // 以太网头(14字节) + ipv4数据包(最大127字节) =  141
            snap_len_v4: 500,
            filter_v4: "icmp || tcp".to_string(),

            conf: Some(mod_conf),
        }
    }

    pub fn init(t:Arc<TopoModV4>, sports:Vec<u16>) -> impl TopoMethodV4 {

        // 第一个参数是t指针, ()内的参数分别为 参数名称, 类型, 默认值, 从SYS中读取的错误提示的标签
        // 可传入多个参数 如: parse_custom_args!(p; (a1, bool, true, "a1_info"), (a2, u32, 0, "a2_info"));
        parse_custom_args!(t;
            (use_time_encoding, bool, true, "use_time_encoding_parse_failed"),
            (topo_udp_dest_port, u16, SYS.get_conf("conf", "topo_udp_dest_port"), "topo_udp_dest_port_parse_failed"),
            (topo_payload, String, SYS.get_conf("conf","topo_payload"), "topo_payload_parse_failed"),
            (topo_payload_allow_repeat, bool, true, "topo_payload_allow_repeat_parse_failed"),
            (topo_allow_tar_network_respond, bool, false, "topo_allow_tar_network_respond_parse_failed")
        );

        let udp_payload = get_payload(topo_payload, topo_payload_allow_repeat, "topo_payload_len_err");

        TopoV4 {
            base_buf: Vec::with_capacity(16),                    // 以太网首部 (14字节) + ipv4首部前两字节 (2字节)
            ipv4_header_base_buf_2: Vec::with_capacity(6),       // ipv4 的 id字段之后 到 地址 之前的 6 字节
            use_time_encoding,
            udp_dest_port:topo_udp_dest_port,
            udp_sports_len: sports.len(),
            udp_sports:sports,
            udp_payload,

            allow_tar_network_respond:topo_allow_tar_network_respond
        }
    }

}

impl Helper for TopoV4 {
    fn print_help() -> String {
        SYS.get_info("help", "TopoV4")
    }
}


fn get_payload(text:String, allow_repeat:bool, err_info:&str) -> Vec<u8> {

    let payload = text.as_bytes();

    if payload.len() < 101 {

        if allow_repeat {

            let repeat_count = (100 / payload.len()) + 1;

            let mut p = Vec::with_capacity(repeat_count * payload.len());
            for _ in 0..repeat_count {
                p.extend_from_slice(payload);
            }

            return p
        } else {
            error!("{}", SYS.get_info("err", err_info));
            exit(1)
        }
    }
    Vec::from(payload)
}