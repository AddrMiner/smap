



use crate::core::receiver::pcap::PcapReceiver;
use crate::modules::probe_modules::probe_mod_v6::ProbeMethodV6;
use crate::tools::check_duplicates::DuplicateCheckerV6Port;
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::packet::v6::packet_v6_u128::Ipv6PacketU128;


impl PcapReceiver  {

    #[inline]
    pub fn pmap_full_scan_handle_packet_v6<B:DuplicateCheckerV6Port>(data_link_header:&[u8], net_layer_header_and_data:&[u8],
                                                                     aes_rand:&AesRand, recorder:&mut B, probe:&Box<dyn ProbeMethodV6>){

        // ipv6 数据包头部
        let v6_header = Ipv6PacketU128::parse_ipv6_packet(net_layer_header_and_data);

        // ipv6 首部长度固定为 40字节  注意: 包含扩展首部
        let net_layer_data = &net_layer_header_and_data[40..];

        if probe.is_successful(data_link_header, &v6_header, net_layer_data, aes_rand) {
            // 如果 目标 端口探测成功

            let src_port = u16::from_be_bytes([net_layer_data[0], net_layer_data[1]]);

            // 直接将  源地址 和 源端口 加入, 多次对 同一端口对 进行标记, 等同于 一次标记
            recorder.set(v6_header.source_addr, src_port)
        }
    }
}