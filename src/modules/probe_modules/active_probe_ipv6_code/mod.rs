mod icmp;

use std::process::exit;
use std::sync::Arc;
use log::error;
use crate::core::conf::modules_config::ModuleConf;
use crate::SYS;
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;

pub use crate::modules::probe_modules::active_probe_ipv6_code::icmp::CodeIcmpEchoV6;

pub const CODE_PROBE_MODS_V6: [&str; 1] = ["code_icmp_v6"];


impl CodeProbeModV6 {
    
    pub fn new(name: &str, conf:ModuleConf) -> CodeProbeModV6 {
        
        if !CODE_PROBE_MODS_V6.contains(&name) {
            error!("{}", SYS.get_info("err", "v6_probe_mod_not_exist"));
            exit(1)
        }

        match name {        // 各类模块的构造方法

            "code_icmp_v6" => CodeIcmpEchoV6::new(conf),

            _ => {
                error!("{}", SYS.get_info("err", "v6_probe_mod_not_exist"));
                exit(1)
            }
        }
    }

    pub fn init(p:Arc<CodeProbeModV6>) -> Box<dyn CodeProbeMethodV6> {

        let name = p.name;

        match name {        // 各类模块的构造方法

            "code_icmp_v6" => Box::new(CodeIcmpEchoV6::init(p)),
            
            _ => {
                error!("{}", SYS.get_info("err", "v6_probe_mod_not_exist"));
                exit(1)
            }
        }
    }
    
}

pub trait CodeProbeMethodV6 {

    // 发送线程初始化
    fn thread_initialize_v6(&mut self, local_mac:&MacAddress, gateway_mac:&MacAddress);

    
    // 生成数据包
    fn make_packet_v6(&self, source_ip:u128, dest_ip:u128, code:Vec<u8>, aes_rand:&AesRand) -> Vec<u8>;
    
    
    // 接收并验证数据包
    // 如果 验证成功, 返回 (区域编码, ipv6地址); 如果 验证失败, 返回 空
    fn receive_packet_v6(&self, net_layer_header:&[u8], net_layer_data:&[u8],  aes_rand:&AesRand) -> Option<(u128, Vec<u8>)>;
}




pub struct CodeProbeModV6 {

    pub name:&'static str,

    pub max_packet_length_v6:usize,
    pub snap_len_v6:usize,
    pub filter_v6:String,
    
    pub code_len:u16,

    pub conf:Option<ModuleConf>,
}

