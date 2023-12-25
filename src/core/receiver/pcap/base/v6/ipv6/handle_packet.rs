use pcap::PacketHeader;
use crate::core::receiver::pcap::PcapReceiver;
use crate::core::receiver::{ReceiverInfoV6};
use crate::modules::output_modules::OutputMethod;
use crate::modules::probe_modules::probe_mod_v6::ProbeMethodV6;
use crate::tools::check_duplicates::DuplicateCheckerV6;
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::packet::v6::packet_v6_u128::Ipv6PacketU128;


impl PcapReceiver  {

    #[inline]
    pub fn handle_packet_v6<B:DuplicateCheckerV6>(header:&PacketHeader, data_link_header:&[u8], net_layer_header_and_data:&[u8],
                            aes_rand:&AesRand, bit_map:&mut B, receiver_info:&mut ReceiverInfoV6,
                            probe:&Box<dyn ProbeMethodV6>, output:&mut Box<dyn OutputMethod>){

        // ipv6 数据包头部
        let v6_header = Ipv6PacketU128::parse_ipv6_packet(net_layer_header_and_data);

        // ipv6 首部长度固定为 40字节  注意: 包含扩展首部
        let net_layer_data = &net_layer_header_and_data[40..];

        let (validation_passed_flag, _, inner_src_ip) = probe.validate_packet_v6(data_link_header, &v6_header,
                                                                              net_layer_data, aes_rand);

        if validation_passed_flag {
            // 如果验证通过
            receiver_info.recv_validation_passed += 1;
        } else {
            // 如果验证失败, 直接退出
            receiver_info.recv_validation_failed += 1;
            return;
        }

        // 如果有内层源地址, 源地址为内层源地址; 如果没有内层源地址, 源地址为数据包的源地址
        let src_ip = inner_src_ip.unwrap_or_else(|| v6_header.source_addr);

        if bit_map.not_marked_and_valid(src_ip) {
            // 对 源地址(如果存在内层源地址, 则为内层源ip) 进行重复检查

            let (is_successful, output_line_data) = probe.process_packet_v6(header, data_link_header,
                                                                            &v6_header, &net_layer_data, inner_src_ip);

            if output_line_data.len() != 0 {
                output.writer_line(&output_line_data);
            }

            if is_successful {
                // 如果 探测成功
                receiver_info.recv_success += 1;
            } else {
                receiver_info.recv_failed += 1;
            }

            // 为 该源地址 做重复标记
            bit_map.set(src_ip);
        } else {
            receiver_info.recv_repeat += 1;
        }
    }
}