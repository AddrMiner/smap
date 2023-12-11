use ahash::AHashSet;
use pcap::PacketHeader;
use crate::core::receiver::pcap::PcapReceiver;
use crate::core::receiver::ReceiverInfoV4;
use crate::modules::output_modules::OutputMethod;
use crate::modules::probe_modules::probe_mod_v4::ProbeMethodV4;
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::packet::v4::packet_v4_u32::Ipv4PacketU32;


impl PcapReceiver  {

    pub fn handle_packet_v4_hash(header:&PacketHeader, data_link_header:&[u8], _data_link_len:u32,net_layer_header_and_data:&[u8],
                            aes_rand:&AesRand, hash_set:&mut AHashSet<(u32, u16)>, receiver_info:&mut ReceiverInfoV4,
                            probe:&Box<dyn ProbeMethodV4>, output:&mut Box<dyn OutputMethod>){

        // ipv4 数据包头部
        let v4_header = Ipv4PacketU32::parse_ipv4_packet(net_layer_header_and_data);

        // 网络层数据
        let net_layer_data = &net_layer_header_and_data[(v4_header.ihl as usize) * 4 ..];

        let (validation_passed_flag, sport, inner_src_ip) = probe.validate_packet_v4(data_link_header, &v4_header,
                                                                                     net_layer_data, aes_rand);

        if validation_passed_flag {
            // 如果验证通过, 表示存在输出项, 比如探测成功得到的输出项, icmp错误消息等
            // 验证通过 不代表 探测成功, 但接收到的数据包 一定是 合法目标的合法数据包
            receiver_info.validation_passed += 1;
        } else {
            // 如果验证失败, 直接退出
            receiver_info.validation_failed += 1;
            return
        }

        // 如果有内层源地址, 源地址为内层源地址; 如果没有内层源地址, 源地址为数据包的源地址
        let src_ip = match inner_src_ip {
            None => v4_header.source_addr,
            Some(ip) => ip,
        };

        if hash_set.contains(&(src_ip, sport)) {
            // 如果 源地址重复
            receiver_info.repeat_total += 1;
        } else {
            // 对 源地址(如果存在内层源地址, 则为内层源ip) 进行重复检查
            // 同一端口对 只有一次输出
            // 注意:所有icmp错误报文均被标记为 0端口, 所有运输层以下协议也均标记为 0端口

            let (is_successful, output_line_data) = probe.process_packet_v4(header, data_link_header,
                                                                            &v4_header, &net_layer_data, inner_src_ip);

            if output_line_data.len() != 0 {
                output.writer_line(&output_line_data);
            }

            if is_successful {
                // 如果 探测成功
                receiver_info.success_total += 1;
            } else {
                receiver_info.failed_total += 1;
            }

            // 为 该源地址 做重复标记
            hash_set.insert((src_ip, sport));
        }
    }
}