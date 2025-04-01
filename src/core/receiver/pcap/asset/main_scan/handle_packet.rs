


use ahash::{AHashMap, AHashSet};
use crate::core::receiver::pcap::PcapReceiver;
use crate::modules::probe_modules::active_probe_ipv6_code::CodeProbeMethodV6;
use crate::tools::encryption_algorithm::aes::AesRand;

impl PcapReceiver {

    pub fn handle_packet_v6_port_vec(
        net_layer_header_and_data:&[u8], aes_rand:&AesRand, probe:&Box<dyn CodeProbeMethodV6>, open_addrs_ports:&AHashMap<u128, u16>, max_port_num:u16,
        hash_set:&mut AHashSet<(u128,u16,u32)>, aliased_prefixes:&AHashSet<u64>, scan_flag:u8, region_len:u32, 
    ){

        // ipv6 首部长度固定为 40字节  注意: 包含扩展首部
        let net_layer_data = &net_layer_header_and_data[40..];

        if let Some((ipv6_addr, dest_port, region_code_vec)) = probe.receive_packet_v6(net_layer_header_and_data, net_layer_data, aes_rand) {
            // 优先判断标识字段
            if region_code_vec[0] != scan_flag { return }

            // 判断当前地址是否在已经探明的别名前缀中
            let cur_prefix = (ipv6_addr >> 64) as u64;
            // 如果当前前缀已经包含在已知别名前缀中, 直接作为无效目标
            if aliased_prefixes.contains(&cur_prefix) { return }

            if let Some(ports_num) = open_addrs_ports.get(&ipv6_addr) {
                // 如果之前已经统计过该地址， 并知道其 开放端口数量

                if *ports_num >= max_port_num {
                    // 如果 已知开放端口的数量 大于等于 最大开放端口数量
                    // 禁止对应目标接收
                    return
                }
            }
            

            // 警告: 处理区域编码
            let region_code = u32::from_be_bytes([0, region_code_vec[1], region_code_vec[2], region_code_vec[3]]);
            if region_code >= region_len { return }

            hash_set.insert((ipv6_addr, dest_port, region_code));
        }
    }


}

// // 输出 探活到的 ipv6地址, 目的地址
//                 output.writer_line(&vec![Ipv6Addr::from(ipv6_addr).to_string(), dest_port.to_string()]);