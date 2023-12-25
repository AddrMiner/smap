

use crate::core::receiver::pcap::PcapReceiver;
use crate::modules::probe_modules::probe_mod_v4::ProbeMethodV4;
use crate::tools::check_duplicates::DuplicateCheckerV4Port;
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::packet::v4::packet_v4_u32::Ipv4PacketU32;


impl PcapReceiver  {

    #[inline]
    pub fn pmap_full_scan_handle_packet_v4<B:DuplicateCheckerV4Port>(data_link_header:&[u8], net_layer_header_and_data:&[u8],
                            aes_rand:&AesRand, recorder:&mut B, probe:&Box<dyn ProbeMethodV4>){

        // ipv4 数据包头部
        let v4_header = Ipv4PacketU32::parse_ipv4_packet(net_layer_header_and_data);

        // 网络层数据
        let net_layer_data = &net_layer_header_and_data[(v4_header.ihl as usize) * 4 ..];

        if probe.is_successful(data_link_header, &v4_header, net_layer_data, aes_rand) {
            // 如果 目标 端口探测成功

            let src_port = u16::from_be_bytes([net_layer_data[0], net_layer_data[1]]);

            // 直接将  源地址 和 源端口 加入, 多次对 同一端口对 进行标记, 等同于 一次标记
            recorder.set(v4_header.source_addr, src_port)
        }
    }
}