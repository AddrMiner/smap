use std::process::exit;
use std::str::FromStr;
use ahash::AHashMap;
use log::error;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::SYS;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;

impl BaseConf {
    
    /// 根据输入的参数建立  接口名称 -> 网关硬件地址的映射
    pub fn get_interface_to_gateway(interface_to_gateway:&Vec<String>) -> AHashMap<String, MacAddress> {
        let mut i2g_map:AHashMap<String, MacAddress> = AHashMap::with_capacity(interface_to_gateway.len());
        
        for i2g in interface_to_gateway {
            let mut i2g_split = i2g.split("@");
            
            match i2g_split.next() {
                Some(interface_name) => {
                    match i2g_split.next() {
                        Some(gateway_mac_str) => {
                            
                            match MacAddress::from_str(gateway_mac_str) {
                                Ok(gateway_mac) => {
                                    i2g_map.insert(String::from(interface_name), gateway_mac);
                                }
                                Err(_) => {
                                    // 解析失败
                                    error!("{} {}", SYS.get_info("err", "parse_gateway_mac_err"), i2g);
                                    exit(1)
                                }
                            }
                        }
                        None => {
                            // 解析失败
                            error!("{} {}", SYS.get_info("err", "parse_gateway_mac_err"), i2g);
                            exit(1)
                        }
                    }
                }
                None => {
                    // 解析失败
                    error!("{} {}", SYS.get_info("err", "parse_gateway_mac_err"), i2g);
                    exit(1)
                },
            }
        }
        
        i2g_map
    }
    
    
}