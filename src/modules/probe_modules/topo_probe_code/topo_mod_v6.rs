use std::process::exit;
use std::sync::Arc;
use libc::timeval;
use log::error;
use crate::core::conf::modules_config::ModuleConf;
use crate::modules::probe_modules::topo_probe_code::v6::icmp::CodeTopoIcmpV6;
use crate::SYS;
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;



pub const CODE_TOPO_PROBE_MODS_V6: [&str; 1] = ["code_topo_icmp_v6"];


impl CodeTopoProbeModV6 {

    pub fn new(name: &str, conf:ModuleConf) -> CodeTopoProbeModV6 {

        if !CODE_TOPO_PROBE_MODS_V6.contains(&name) {
            error!("{}", SYS.get_info("err", "v6_probe_mod_not_exist"));
            exit(1)
        }

        match name {        // 各类模块的构造方法

            "code_topo_icmp_v6" => CodeTopoIcmpV6::new(conf),

            _ => {
                error!("{}", SYS.get_info("err", "v6_probe_mod_not_exist"));
                exit(1)
            }
        }
    }

    pub fn init(p:Arc<CodeTopoProbeModV6>) -> Box<dyn CodeTopoProbeMethodV6> {

        let name = p.name;

        match name {        // 各类模块的构造方法

            "code_topo_icmp_v6" => Box::new(CodeTopoIcmpV6::init(p)),

            _ => {
                error!("{}", SYS.get_info("err", "v6_probe_mod_not_exist"));
                exit(1)
            }
        }
    }


}



pub trait CodeTopoProbeMethodV6 {

    fn thread_initialize_v6(&mut self, local_mac:&MacAddress, gateway_mac:&MacAddress);


    fn make_packet_v6(&self, source_ip:u128, dest_ip:u64, hop_limit:u8, code:Vec<u8>, aes_rand:&AesRand) -> Vec<u8>;

    // 接收并验证数据包
    // 如果 验证成功, 返回 (区域编码, ipv6地址); 如果 验证失败, 返回 空
    fn receive_packet_v6(&self, ts: &timeval, net_layer_header:&[u8], net_layer_data:&[u8],  aes_rand:&AesRand) -> Option<CodeTopoResultV6>;
    
    #[allow(dead_code)]
    fn print_header(&self) -> Vec<String>;
    fn print_record(&self, res:&CodeTopoResultV6) -> Vec<String>;
}



pub struct CodeTopoResultV6 {
    pub dest_ip:u128,    // 发送时的 目的地址
    pub responder:u128,  // 响应的 源地址
    pub init_ttl:u8,     // 起始ttl

    pub from_destination:bool, // 是否是来自 目的地址 的响应
    
    pub rtt:u32,        // 往返时延 以毫秒为单位

    pub code:Vec<u8>,        // 编码字节数组
}



pub struct CodeTopoProbeModV6 {
    pub name:&'static str,

    pub max_packet_length_v6:usize,
    pub snap_len_v6:usize,
    pub filter_v6:String,

    pub code_len:u16,

    #[allow(dead_code)]
    pub conf:Option<ModuleConf>,
}