use ahash::AHashSet;
use crate::core::receiver::pcap::PcapReceiver;
use crate::modules::probe_modules::active_probe_ipv6_code::CodeProbeMethodV6;
use crate::tools::encryption_algorithm::aes::AesRand;

impl PcapReceiver {

    pub fn handle_packet_asset_aliased_check(
        net_layer_header_and_data:&[u8], aes_rand:&AesRand, probe:&Box<dyn CodeProbeMethodV6>,
        hash_set:&mut AHashSet<u128>, region_recorder:&mut Vec<u64>, scan_flag:u8,
    ){

        // ipv6 首部长度固定为 40字节  注意: 包含扩展首部
        let net_layer_data = &net_layer_header_and_data[40..];

        if let Some((ipv6_addr, _, region_code_vec)) = probe.receive_packet_v6(net_layer_header_and_data, net_layer_data, aes_rand) {
            // 优先判断标识字段
            if region_code_vec[0] != scan_flag { return }

            if !hash_set.contains(&ipv6_addr) {
                // 警告: 处理区域编码
                let region_code = u32::from_be_bytes([0, region_code_vec[1], region_code_vec[2], region_code_vec[3]]);

                let region_len = region_recorder.len() as u32;
                if region_code >= region_len { return }

                region_recorder[region_code as usize] += 1;

                hash_set.insert(ipv6_addr);
            }
        }
    }


}