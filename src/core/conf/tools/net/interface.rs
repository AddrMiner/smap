use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use libc::{c_int};
use crate::tools::net_handle::net_interface::interface::NetInterface;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;
use crate::tools::net_handle::net_type::net_v4::Netv4;
use crate::tools::net_handle::net_type::net_v6::Netv6;
use std::process::exit;
use log::error;
use crate::SYS;

/// 网络接口配置信息
pub struct InterfaceConf {

    pub name_index:(String, c_int),

    // 网关地址
    pub gateway_mac:MacAddress,
    pub gateway_ip:IpAddr,


    // 本地硬件地址
    pub local_mac:MacAddress,

    // 本地 ip 和 网络  注意 ip 和 net 的下标应该对应一致
    pub local_ipv4:Vec<Ipv4Addr>,
    pub local_ipv4_net:Vec<Netv4>,

    pub local_ipv6:Vec<Ipv6Addr>,
    pub local_ipv6_net:Vec<Netv6>,

    // 传输接收速度
    pub receive_speed:Option<u64>,
    pub transmit_speed:Option<u64>

}



impl InterfaceConf {

    /// 网络接口配置
    /// 如果传入 Some(接口名称)，查询对应接口的信息并配置
    /// 如果传入 None, 将使用默认网络接口
    pub fn new(interface_name:Option<String>) -> Self {

        let selected_interface = NetInterface::new(interface_name);

        // 获取选定的 接口名称
        let selected_interface_name = selected_interface.interface.name;

        // 解析网关 mac 和 ip
        let gateway_mac;
        let gateway_ip;
        {
            // 未给定 网关mac地址, 将从 interface 获取
            let gateway = selected_interface.interface.gateway;

            // 获取网关 ip
            if let Some(g) = gateway {
                gateway_ip = g.ip_addr;
                gateway_mac = MacAddress::from_mac_addr(g.mac_addr);
            } else {
                error!("{} {}", SYS.get_info("err", "gateway_info_not_found"), selected_interface_name);
                exit(1)
            }
        }

        // 解析 网络接口 mac地址
        let local_mac = match selected_interface.interface.mac_addr{
            Some(m) => {
                MacAddress::from_mac_addr(m)
            }
            None => {
                error!("{} {}", SYS.get_info("err", "local_mac_not_found"), selected_interface_name);
                exit(1)
            }
        };

        // 解析 网络接口 ipv4 和 ipv6
        let mut local_ipv4:Vec<Ipv4Addr> = vec![];
        let mut local_ipv4_net:Vec<Netv4> = vec![];
        let mut local_ipv6:Vec<Ipv6Addr> = vec![];
        let mut local_ipv6_net:Vec<Netv6> = vec![];
        {
            let local_ipv4_info = selected_interface.interface.ipv4;
            let local_ipv6_info = selected_interface.interface.ipv6;

            for net_v4 in local_ipv4_info.iter() {
                local_ipv4.push(net_v4.addr);
                local_ipv4_net.push(Netv4::new(net_v4.addr, net_v4.prefix_len));
            }

            for net_v6 in local_ipv6_info.iter() {
                local_ipv6.push(net_v6.addr);
                local_ipv6_net.push(Netv6::new(net_v6.addr, net_v6.prefix_len));
            }
        }

        Self {
            name_index: (selected_interface_name, selected_interface.interface.index as c_int),

            gateway_mac,
            gateway_ip,

            local_mac,

            local_ipv4,
            local_ipv4_net,

            local_ipv6,
            local_ipv6_net,

            receive_speed: selected_interface.interface.receive_speed,
            transmit_speed: selected_interface.interface.transmit_speed,
        }


    }

    /// 设置 网关硬件地址
    /// 需要注意与 网络接口 的网关地址不一致造成的影响
    #[allow(dead_code)]
    pub fn set_gateway_mac(&mut self, mac:MacAddress){
        self.gateway_mac = mac;
    }


    /// 设置 网关ip地址
    /// 需要注意与 网络接口 的网关地址不一致造成的影响
    #[allow(dead_code)]
    pub fn set_gateway_ip(&mut self, ip:IpAddr){
        self.gateway_ip = ip;
    }


    /// 设置 本地硬件地址
    /// 需要注意与 网络接口 的网关地址不一致造成的影响
    #[allow(dead_code)]
    pub fn set_local_mac(&mut self, mac:MacAddress){
        self.local_mac = mac;
    }

}
