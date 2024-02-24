use pcap::PacketHeader;
use std::net::Ipv4Addr;
use crate::modules::probe_modules::probe_mod_v4::ProbeMethodV4;
use crate::modules::probe_modules::tools::ethernet::make_ethernet_header;
use crate::{push_fields_name, push_fields_val};
use crate::modules::probe_modules::v4::tcp::tcp_syn_opt::TcpSynOptV4;
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;
use crate::tools::net_handle::packet::tcp::opt::opt_fields::TcpOptFields;
use crate::tools::net_handle::packet::tcp::TcpPacket;
use crate::tools::net_handle::packet::v4::packet_v4_u32::Ipv4PacketU32;

impl ProbeMethodV4 for TcpSynOptV4 {
    fn thread_initialize_v4(&mut self, local_mac: &MacAddress, gateway_mac: &MacAddress, rand_u16: u16) {
        //  填充以太网首部字段 14字节       以太网类型为 ipv4 在以太网类型字段中的标识
        make_ethernet_header(&mut self.base_buf, local_mac, gateway_mac, 0x0800u16);

        self.base_buf.extend(Ipv4PacketU32 {
            ihl: 5,                  // 首部长度为 5 * 4 = 20字节
            tos: 0,                  // 服务类型
            total_len: 20 + (self.tcp_len as u16),           // 长度为 ipv4首部(20字节) + tcp报文

            // 16位标识唯一地标识主机发送的每一个数据报。每发送一个数据报，其值就加1。该值在数据报分片时被复制到每个分片中，因此同一个数据报的所有分片都具有相同的标识值。
            // 警告: 该固定字段可用于识别 扫描流量, 隐秘化扫描应使用随机值
            id: rand_u16,

            rf: 0,
            df: 0,
            mf: 0,
            offset: 0,

            ttl: 64,                // 初始ttl
            protocol: 6,            // tcp 在 ipv4 中的协议号为 6

            // 无论该项输入是什么, 输出字节数组时都会被置为 0
            header_check_sum: 0,
            // 以下几项无效, 不会出现在得到的字节数组中
            source_addr: 0,
            dest_addr: 0,
        }.get_u8_vec_without_addr());

        self.tcp_header_after_seq.extend(TcpPacket {
            // 以下三项无效, 也不会传入
            sport: 0,
            dport: 0,
            sequence_num: 0,

            ack_num: 0,
            header_len: 5 + ((self.opt_payload.len() / 4) as u8),      // 5*4=20字节基本首部
            urg: 0,
            ack: 0,
            psh: 0,
            rst: 0,
            syn: 1,
            fin: 0,
            window_size: 65535,
            check_sum: 0,        // 该项无效, 获取字节数组时将被自动设置为 0
            urgent_pointer: 0,
        }.get_u8_vec_after_sequence());
    }

    fn make_packet_v4(&self, source_ip: u32, dest_ip: u32, dest_port: u16, ttl: Option<u8>, aes_rand: &AesRand) -> Vec<u8> {
        let mut packet = Vec::with_capacity(self.max_len);

        let source_ip_bytes = source_ip.to_be_bytes();
        let dest_ip_bytes = dest_ip.to_be_bytes();
        {
            // 以太网报头: [ 目的地址: { 0, 1, 2, 3, 4, 5}  源地址: { 6, 7, 8, 9, 10, 11 }  标识 { 12, 13 } ]
            // ipv4 报头: [ 版本号: {14( 1111_0000 ) }, 首部长度: {14( 0000_1111 )}, 服务类型: {15} ]
            //           [ 总长度: {16, 17}, id: {18, 19}, 标志: rf:{20 (1_000_0000), df:20 (0_1_00_0000), mf:20 (00_1_0_0000)}]
            //           [ 片偏移: {20 (000_11111), 21}, ttl: {22}, 协议: {23}, 校验和: {24, 25}]
            //           [ 源地址: {26, 27, 28, 29}, 目的地址: {30, 31, 32, 33} ]

            // 写入 以太网首部, 不含地址的 ipv4首部
            packet.extend_from_slice(&self.base_buf);

            if let Some(t) = ttl { packet[22] = t; }

            // 写入 ipv4源地址
            packet.extend(source_ip_bytes);

            // 写入 ipv4目的地址
            packet.extend(dest_ip_bytes);

            // 写入 ipv4首部校验和
            let checksum = Ipv4PacketU32::get_check_sum_from_buf(&packet[14..34]);
            packet[24] = checksum[0];
            packet[25] = checksum[1];
        }

        let validation = aes_rand.validate_gen_v4_u32(source_ip, dest_ip, &dest_port.to_be_bytes());
        {
            // tcp 报头(20字节): [ 源端口: {34, 35}   目的端口: {36, 37} ]
            //                  [ 序列号: {38, 39, 40, 41} ]
            //                  [ 确认号: {42, 43, 44, 45} ]
            //                  [ 数据偏移: {46(1111_0000)}  保留字段:{46(0000_1111), 47(11_000000)} 标记字段:{47(00_111111)} 窗口:{48, 49} ]
            //                  [ 校验和: {50, 51} 紧急指针{52, 53} ]
            //    tcp 选项:      [ 负载: {54, <总长度} ]

            // 写入 源端口 (2字节)
            {   // 下标为 0..len-1(最大为65535),  以验证字段前两个字节作为随机索引, 从源端口向量中提取源端口
                let sport_index = ((validation[0] as usize) << 8) | (validation[1] as usize);
                let sport = self.sports[ sport_index % self.sports_len ];
                packet.extend(sport.to_be_bytes());
            }

            // 写入 目标端口 (2字节)
            packet.extend(dest_port.to_be_bytes());

            // 写入 序列号 (4字节)   将验证数据的 前4字节 作为 序列号
            packet.extend(&validation[0..4]);

            // 写入 tcp首部 序列号以后的部分 (12字节)
            packet.extend_from_slice(&self.tcp_header_after_seq);

            // 写入 tcp 选项部分
            packet.extend_from_slice(&self.opt_payload);

            let tcp_check_sum_bytes = TcpPacket::get_check_sum_v6(&source_ip_bytes, &dest_ip_bytes, self.tcp_len, &packet[34..self.max_len]);
            packet[50] = tcp_check_sum_bytes[0];
            packet[51] = tcp_check_sum_bytes[1];
        }
        packet
    }

    fn is_successful(&self, _data_link_header:&[u8], ipv4_header:&Ipv4PacketU32, net_layer_data:&[u8], aes_rand:&AesRand) -> bool {
        if ipv4_header.protocol != 6 || net_layer_data.len() < 20 || ((net_layer_data[13] >> 2) & 1) == 1 { return false }

        let validation = aes_rand.validate_gen_v4_u32(ipv4_header.dest_addr, ipv4_header.source_addr, &net_layer_data[0..2]);
        {   // 判断 接收到的数据包的 目的端口(本机源端口) 是否 正确
            // 数据包的 源端口(探测的目标端口), 已在 验证字段 中进行检查, 验证字段的输入为 三元组(源地址, 目的地址, 目的端口)
            let dport = ((net_layer_data[2] as u16) << 8) | (net_layer_data[3] as u16);

            let local_sport_index = ((validation[0] as usize) << 8) | (validation[1] as usize);
            let local_sport = self.sports[ local_sport_index % self.sports_len ];

            if dport != local_sport { return false }
        }

        let sent_seq = u32::from_be_bytes([validation[0], validation[1], validation[2], validation[3]]);
        let ack = u32::from_be_bytes([net_layer_data[8], net_layer_data[9], net_layer_data[10], net_layer_data[11]]);
        // 响应数据包 中的 确认号 应该为 (发送时的序列号 + 1)
        ack == (sent_seq + 1)
    }

    fn validate_packet_v4(&self, _data_link_header: &[u8], ipv4_header: &Ipv4PacketU32, net_layer_data: &[u8], aes_rand: &AesRand) -> (bool, u16, Option<u32>) {
        if ipv4_header.protocol != 6 || net_layer_data.len() < 20 {
            // 如果ipv4首部中的 下一首部 字段不是 6(tcp), 返回 验证失败
            // 网络层数据必须至少为 20字节(tcp首部)

            return (false, 0, None)
        }

        let validation = aes_rand.validate_gen_v4_u32(ipv4_header.dest_addr, ipv4_header.source_addr, &net_layer_data[0..2]);
        {   // 判断 接收到的数据包的 目的端口(本机源端口) 是否 正确
            // 数据包的 源端口(探测的目标端口), 已在 验证字段 中进行检查, 验证字段的输入为 三元组(源地址, 目的地址, 目的端口)
            let dport = ((net_layer_data[2] as u16) << 8) | (net_layer_data[3] as u16);

            let local_sport_index = ((validation[0] as usize) << 8) | (validation[1] as usize);
            let local_sport = self.sports[ local_sport_index % self.sports_len ];

            if dport != local_sport {
                // 如果 接收到的数据包的 目的端口, 与本机对应的源端口不一致
                return (false, 0, None)
            }
        }

        let sent_seq = u32::from_be_bytes([validation[0], validation[1], validation[2], validation[3]]);
        let ack = u32::from_be_bytes([net_layer_data[8], net_layer_data[9], net_layer_data[10], net_layer_data[11]]);

        if ack == (sent_seq + 1) {
            // 响应数据包 中的 确认号 应该为 (发送时的序列号 + 1)
            (true, u16::from_be_bytes([net_layer_data[0], net_layer_data[1]]), None)
        } else {
            (false, 0, None)
        }
    }

    fn print_header(&self) -> Vec<String> {
        let mut output_data = Vec::with_capacity(self.fields_flag.len);
        push_fields_name!(self; output_data; source_addr,sport,
            dport,seq_num,ack_num,window,
            opt_text,tcp_mss,ts_val,ts_ecr,ts_diff,qs_func,qs_ttl,qs_nonce,echo,echo_reply,ws_cale,mp_tcp_key,mp_tcp_diff,tfo_cookie,
           classification, bytes);
        output_data
    }

    fn process_packet_v4(&self, _header: &PacketHeader, _data_link_header: &[u8], ipv4_header: &Ipv4PacketU32, net_layer_data: &[u8], _inner_ip: Option<u32>) -> (bool, Vec<String>) {
        let mut output_data = Vec::with_capacity(self.fields_flag.len);
        push_fields_val!(self; output_data; (source_addr, Ipv4Addr::from(ipv4_header.source_addr)));

        let rst;
        if self.fields_flag.tcp_fields_exist {
            let tcp_header = TcpPacket::from(net_layer_data);
            rst = tcp_header.rst == 1;

            push_fields_val!(self; output_data; (sport, tcp_header.sport), (dport, tcp_header.dport),
                (seq_num, tcp_header.sequence_num), (ack_num, tcp_header.ack_num), (window, tcp_header.window_size));
        } else {
            rst = ((net_layer_data[13] >> 2) & 1) == 1;

            if self.fields_flag.sport {
                let sport = ((net_layer_data[0] as u16) << 8) | (net_layer_data[1] as u16);
                output_data.push(sport.to_string());
            }
        }

        if self.fields_flag.tcp_opt_exist {
                                                                                                    // 这里后移 20字节, 20字节是 tcp固定首部 的长度
            let (opt_text, opt_info) = TcpOptFields::parse_tcp_opt(&net_layer_data[20..]);

            push_fields_val!(self; output_data;
                (opt_text, opt_text),
                (tcp_mss, opt_info.tcp_mss),
                (ts_val, opt_info.ts_val),
                (ts_ecr, opt_info.ts_ecr),
                (ts_diff, opt_info.ts_diff),
                (qs_func, opt_info.qs_func),
                (qs_ttl, opt_info.qs_ttl),
                (qs_nonce, opt_info.qs_nonce),
                (echo, opt_info.echo),
                (echo_reply, opt_info.echo_reply),
                (ws_cale, opt_info.ws_cale),
                (mp_tcp_key, opt_info.mp_tcp_key),
                (mp_tcp_diff, opt_info.mp_tcp_diff),
                (tfo_cookie, opt_info.tfo_cookie)
            );
        }

        if self.fields_flag.classification {
            if rst {
                output_data.push("rst".to_string());
            } else {
                output_data.push("syn_ack".to_string());
            }
        }

        push_fields_val!(self; output_data;  (bytes, format!("{:?}", &net_layer_data[20..])));

        (!rst, output_data)
    }
}