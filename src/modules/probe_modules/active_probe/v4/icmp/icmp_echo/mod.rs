mod method;

use std::sync::Arc;
use crate::core::conf::modules_config::ModuleConf;
use crate::modes::Helper;
use crate::modules::probe_modules::probe_mod_v4::{ProbeMethodV4, ProbeModV4};
use crate::modules::probe_modules::tools::payload::get_payload;
use crate::{not_use_port_check, SYS};
use crate::tools::file::get_path::get_current_path;
use crate::tools::net_handle::packet::v4::icmp_v4::fields::IcmpV4Fields;


pub struct IcmpEchoV4 {

    base_buf:Vec<u8>,
    max_len:usize,

    payload: Vec<u8>,

    print_ipv4_packet:bool,
    fields_flag:IcmpV4Fields
}


impl IcmpEchoV4 {   // 定义构造方法和初始化方法

    pub fn new(mod_conf:ModuleConf, tar_ports:&Vec<u16>, seed:u64, fields:&Vec<String>) -> ProbeModV4 {         // 输出模块创建， 用于初始化参数配置

        // 不使用端口的模块, 强制目标端口为 0
        not_use_port_check!(tar_ports);

        // 得到 payload文件路径
        let payload_path = get_current_path(&SYS.get_info("conf", "default_payload_file"));

        // 根据自定义参数 payload, 得到具体的 payload字节向量
        let payload = get_payload(mod_conf.get_info(&"payload".to_string()),
                                  payload_path, seed,0, 8);

        ProbeModV4 {
            name:"icmp_v4",

            max_packet_length_v4: 42 + payload.len(),                       // 数据链路层报头(14字节) + ipv4报头(20字节) + icmp_v4报头(8字节) + icmp载荷 = 42字节 +
            snap_len_v4: 96,
            filter_v4: "icmp and icmp[0]!=8".to_string(),

            use_tar_ports: false,

            // 运输层选项字段
            option: vec![],
            // 运输层上层协议
            payload,

            fields:fields.clone(),
            conf:None,
        }

    }

    pub fn init(p:Arc<ProbeModV4>) -> impl ProbeMethodV4 {

        let mut fields_flag = IcmpV4Fields::new(&p.fields);
        
        let print_ipv4_packet;
        if p.fields.contains(&"ipv4_packet".to_string()) {             
            fields_flag.len += 13;      
            print_ipv4_packet = true;
        } else { 
            print_ipv4_packet = false;
        }
        

        IcmpEchoV4 {
            // 以太网头 14字节, 没有地址的ipv4首部 12字节       14 + 12 = 26
            base_buf: Vec::with_capacity(26),
            max_len: p.max_packet_length_v4,

            payload: p.payload.clone(),

            print_ipv4_packet,
            fields_flag,
        }

    }
}

impl Helper for IcmpEchoV4 {

    fn print_help() -> String {
        SYS.get_info("help", "IcmpEchoV4")
    }

}
