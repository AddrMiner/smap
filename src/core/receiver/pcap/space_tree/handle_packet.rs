use std::net::Ipv6Addr;
use ahash::AHashSet;
use crate::core::receiver::pcap::PcapReceiver;
use crate::modules::output_modules::OutputMethod;
use crate::modules::probe_modules::active_probe_ipv6_code::CodeProbeMethodV6;
use crate::tools::encryption_algorithm::aes::AesRand;

impl PcapReceiver {

    pub fn handle_packet_v6_vec(
        net_layer_header_and_data:&[u8], aes_rand:&AesRand, probe:&Box<dyn CodeProbeMethodV6>,
        output:&mut Box<dyn OutputMethod>, hash_set:&mut AHashSet<u128>, region_recorder:&mut Vec<u64>
    ){

        // ipv6 首部长度固定为 40字节  注意: 包含扩展首部
        let net_layer_data = &net_layer_header_and_data[40..];
        
        if let Some((ipv6_addr, region_code_vec)) = probe.receive_packet_v6(net_layer_header_and_data, net_layer_data, aes_rand) {

            // 去除重复的
            if !hash_set.contains(&ipv6_addr) {
                
                // 输出 探活到的 ipv6地址
                output.writer_line(&vec![Ipv6Addr::from(ipv6_addr).to_string()]);
                
                // 将 区域编码 进行记录
                let region_code = ((region_code_vec[0] as u16) << 8) | (region_code_vec[1] as u16);
                region_recorder[region_code as usize] += 1;
                
                hash_set.insert(ipv6_addr);
            }
        }
    }
    
    
}