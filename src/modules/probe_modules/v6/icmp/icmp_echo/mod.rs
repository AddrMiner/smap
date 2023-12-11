mod method;

use std::sync::Arc;
use log::error;
use crate::modes::Helper;
use crate::modules::probe_modules::probe_mod_v6::{ProbeMethodV6, ProbeModV6};
use crate::SYS;
use crate::tools::net_handle::packet::v6::icmp_v6::fields::IcmpV6Fields;
use std::process::exit;


pub struct IcmpEchoV6 {

    base_buf:Vec<u8>,
    max_len:usize,

    fields_flag:IcmpV6Fields
}


impl IcmpEchoV6 {   // 定义构造方法和初始化方法

    pub fn new(tar_ports:&Vec<u16>, fields:&Vec<String>) -> ProbeModV6 {         // 输出模块创建， 用于初始化参数配置

        if tar_ports.len() != 1 {
            // 如果有 多个端口 或 没有输入端口
            error!("{}", SYS.get_info("err", "tar_ports_not_match_net_layer"));
            exit(1)
        } else {
            if tar_ports[0] != 0 {
                // 如果输出的目标端口不为0
                error!("{}", SYS.get_info("err", "tar_ports_not_match_net_layer"));
                exit(1)
            }
        }

        ProbeModV6 {
            name:"icmp_v6",

            max_packet_length_v6: 70,       // 以太网首部(14字节) + ipv6报头(40字节) + icmp报头(8字节) + icmp数据(8字节) = 70
            snap_len_v6: 118,               // 以太网首部(14字节) + 外层ipv6报头(40字节) + 外层icmp_v6报头(8字节) + 内层ipv6报头(40字节) + 内层icmp_v6报头(8字节)  + icmp_v6数据(8字节) = 118
            filter_v6: "icmp6 && (ip6[40] == 129 || ip6[40] == 3 || ip6[40] == 1 || ip6[40] == 2 || ip6[40] == 4)".to_string(),
            option: vec![],
            payload: vec![],
            fields:fields.clone(),
            conf:None
        }

    }

    pub fn init(p:Arc<ProbeModV6>) -> impl ProbeMethodV6 {

        IcmpEchoV6 {
            // 以太网头 14字节, 没有地址的ipv6首部 8字节       14 + 8 = 22
            base_buf: Vec::with_capacity(22),
            max_len: p.max_packet_length_v6,
            fields_flag: IcmpV6Fields::new(&p.fields),
        }

    }
}

impl Helper for IcmpEchoV6 {

    fn print_help() -> String {
        SYS.get_info("help", "IcmpEchoV6")
    }

}