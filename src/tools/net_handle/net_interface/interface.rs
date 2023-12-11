use std::process::exit;
use default_net::{get_default_interface, get_interfaces, Interface};
use log::error;
use crate::SYS;

/// 定义网络接口
pub struct NetInterface {
    pub interface:Interface
}


impl NetInterface {

    /// 构造网络接口配置
    /// 如果指定了接口名称, 就返回对应接口的信息, 如果未查询到指定接口会报错
    /// 如果未指定接口(None), 就返回默认接口
    pub fn new(name: Option<String>) -> Self {

        if let Some(interface_name) = name {
            // 指定接口

            let interfaces = get_interfaces();

            for i in interfaces {

                if i.name == interface_name {

                    let mut tar_interface = i;
                    if cfg!(target_os = "windows") {
                        tar_interface.name = format!("{}{}","\\Device\\NPF_", interface_name);
                    }

                    return NetInterface {
                        interface:tar_interface,
                    };

                }

            }

            // 查询了全部的接口信息, 但是没有找到对应接口
            error!("{} {}", SYS.get_info("err","interface_not_found"), interface_name);
            exit(1)

        } else { // 未指定接口

            let mut tar_interface = get_default_interface().map_err(|_|{

                // 无法获取默认接口
                error!("{}", SYS.get_info("err", "default_interface_not_found"));
                exit(1)
            }).unwrap();

            if cfg!(target_os = "windows") {
                tar_interface.name = format!("{}{}","\\Device\\NPF_", tar_interface.name);
            }

            return NetInterface {
                // 使用默认接口
                interface: tar_interface,
            };

        }

    }



}