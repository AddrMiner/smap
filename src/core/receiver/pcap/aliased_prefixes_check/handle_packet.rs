use ahash::AHashSet;
use crate::core::receiver::pcap::PcapReceiver;
use crate::modules::probe_modules::active_probe_ipv6_code::CodeProbeMethodV6;
use crate::tools::encryption_algorithm::aes::AesRand;

impl PcapReceiver {

    pub fn handle_packet_v6_alia(
        net_layer_header_and_data:&[u8], aes_rand:&AesRand, probe:&Box<dyn CodeProbeMethodV6>,
        hash_set:&mut AHashSet<u128>, recorder:&mut Vec<u8>
    ){

        // ipv6 首部长度固定为 40字节  注意: 包含扩展首部
        let net_layer_data = &net_layer_header_and_data[40..];

        if let Some((ipv6_addr, code_vec)) = probe.receive_packet_v6(net_layer_header_and_data, net_layer_data, aes_rand) {

            // 去除重复的
            if !hash_set.contains(&ipv6_addr) {

                // 将 编码 进行记录
                let code = u32::from_be_bytes([code_vec[0], code_vec[1], code_vec[2], code_vec[3]]);
                recorder[code as usize] += 1;

                hash_set.insert(ipv6_addr);
            }
        }
    }


}