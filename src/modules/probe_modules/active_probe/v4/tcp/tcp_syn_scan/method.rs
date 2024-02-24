use std::net::Ipv4Addr;
use pcap::PacketHeader;
use crate::modules::probe_modules::probe_mod_v4::ProbeMethodV4;
use crate::modules::probe_modules::tools::ethernet::make_ethernet_header;
use crate::{push_fields_name, push_fields_val};
use crate::modules::probe_modules::v4::tcp::tcp_syn_scan::TcpSynScanV4;
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;
use crate::tools::net_handle::packet::tcp::TcpPacket;
use crate::tools::net_handle::packet::v4::icmp_v4::ICMP_UNREACH;
use crate::tools::net_handle::packet::v4::packet_v4_u32::Ipv4PacketU32;

impl ProbeMethodV4 for TcpSynScanV4 {
    fn thread_initialize_v4(&mut self, local_mac: &MacAddress, gateway_mac: &MacAddress, rand_u16:u16) {
        //  填充以太网首部字段 14字节       以太网类型为 ipv4 在以太网类型字段中的标识
        make_ethernet_header(&mut self.base_buf, local_mac, gateway_mac, 0x0800u16);

        //  填充没有 地址 的ipv4首部字段  12字节
        self.base_buf.extend(Ipv4PacketU32 {
            ihl: 5,                  // 首部长度为 5 * 4 = 20字节
            tos: 0,                  // 服务类型
            total_len: 44,           // 长度为 ipv4首部(20字节) + tcp报文(24字节) = 44 字节

            // 16位标识唯一地标识主机发送的每一个数据报。每发送一个数据报，其值就加1。该值在数据报分片时被复制到每个分片中，因此同一个数据报的所有分片都具有相同的标识值。
            // 警告: 该固定字段可用于识别 扫描流量, 隐秘化扫描应使用随机值
            id: rand_u16,

            rf: 0,
            df: 0,
            mf: 0,
            offset: 0,

            ttl: 64,               // 初始ttl
            protocol: 6,            // tcp 在 ipv4 中的协议号为 6

            // 无论该项输入是什么, 输出字节数组时都会被置为 0
            header_check_sum: 0,
            // 以下几项无效, 不会出现在得到的字节数组中
            source_addr: 0,
            dest_addr: 0,
        }.get_u8_vec_without_addr());

        { // 获取 tcp首部序列号之后的部分, 注意包含check_sum    12字节(基本首部) + 4字节(mss选项字段)
            let tcp_header = TcpPacket {
                // 以下三项无效, 也不会传入
                sport: 0,
                dport: 0,
                sequence_num: 0,

                ack_num: 0,
                header_len: 6,      // 5*4=20字节基本首部   1*4=4字节mss字段(kind(1字节), len(1字节), mss_info(2字节))  共计 6*4= 24字节
                urg: 0,
                ack: 0,
                psh: 0,
                rst: 0,
                syn: 1,
                fin: 0,
                window_size: 65535,
                check_sum: 0,        // 该项无效, 获取字节数组时将被自动设置为 0
                urgent_pointer: 0,
            };
            self.tcp_header_after_seq.extend(tcp_header.get_u8_vec_after_sequence());
            self.tcp_header_after_seq.extend(TcpPacket::get_mss_option());
        }
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
            // tcp 选项(4字节):  [ 类型: {54}  长度(包括类型和长度字段所占的字节数): {55}  mss字段: {56, 57}]

            // 写入 源端口 (2字节)   注意: 只要validation确定(源地址, 目的地址, 目标端口的组合确定), 得到的源端口就是确定的
            {   // 下标为 0..len-1(最大为65535),  以验证字段前两个字节作为随机索引, 从源端口向量中提取源端口
                let sport_index = ((validation[0] as usize) << 8) | (validation[1] as usize);
                let sport = self.sports[ sport_index % self.sports_len ];
                packet.extend(sport.to_be_bytes());
            }

            // 写入 目标端口 (2字节)
            packet.extend(dest_port.to_be_bytes());

            // 写入 序列号 (4字节)   将验证数据的 前4字节 作为 序列号
            packet.extend(&validation[0..4]);

            // 写入 tcp首部(包括mss字段) 序列号以后的部分 (16字节)
            packet.extend_from_slice(&self.tcp_header_after_seq);

            let tcp_check_sum_bytes = TcpPacket::get_check_sum_v4(&source_ip_bytes, &dest_ip_bytes, 24, &packet[34..58]);
            packet[50] = tcp_check_sum_bytes[0];
            packet[51] = tcp_check_sum_bytes[1];
        }
        packet
    }

    fn is_successful(&self, _data_link_header:&[u8], ipv4_header:&Ipv4PacketU32, net_layer_data:&[u8], aes_rand:&AesRand) -> bool {
        if ipv4_header.protocol != 6 || net_layer_data.len() < 20 || ((net_layer_data[13] >> 2) & 1) == 1 {return false}

        let validation = aes_rand.validate_gen_v4_u32(ipv4_header.dest_addr, ipv4_header.source_addr, &net_layer_data[0..2]);
        {   // 判断 接收到的数据包的 目的端口(本机源端口) 是否 正确
            // 数据包的 源端口(探测的目标端口), 已在 验证字段 中进行检查, 验证字段的输入为 三元组(源地址, 目的地址, 目的端口)
            let dport = ((net_layer_data[2] as u16) << 8) | (net_layer_data[3] as u16);

            let local_sport_index = ((validation[0] as usize) << 8) | (validation[1] as usize);
            let local_sport = self.sports[ local_sport_index % self.sports_len ];

            if dport != local_sport { return false }
        }

        let ack = u32::from_be_bytes([net_layer_data[8], net_layer_data[9], net_layer_data[10], net_layer_data[11]]);
        let sent_seq = u32::from_be_bytes([validation[0], validation[1], validation[2], validation[3]]);
        ack == (sent_seq + 1)
    }

    fn validate_packet_v4(&self, _data_link_header: &[u8], ipv4_header: &Ipv4PacketU32, net_layer_data: &[u8], aes_rand: &AesRand) -> (bool, u16, Option<u32>) {

        match ipv4_header.protocol {

            6 => {
                // 网络层数据必须至少为 20字节(tcp首部)
                if net_layer_data.len() < 20 { return (false, 0, None) }

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

                {
                    let ack = u32::from_be_bytes([net_layer_data[8], net_layer_data[9], net_layer_data[10], net_layer_data[11]]);
                    let sent_seq = u32::from_be_bytes([validation[0], validation[1], validation[2], validation[3]]);

                    let rst = (net_layer_data[13] >> 2) & 1;
                    if rst == 1 {
                        if ack == sent_seq || ack == (sent_seq + 1) {
                            (true, u16::from_be_bytes([net_layer_data[0], net_layer_data[1]]), None)
                        } else { (false, 0, None) }
                    } else {
                        if ack == (sent_seq + 1) {
                            (true, u16::from_be_bytes([net_layer_data[0], net_layer_data[1]]), None)
                        } else {
                            (false, 0, None)
                        }
                    }
                }
            }

            1 => {
                // 如果存在 内部ipv4数据包, 则整个网络层的长度至少为  外层icmp报头(8字节) + 内层ipv4报头(20字节) + 原始数据包前8字节(8字节)
                if net_layer_data.len() < 36 { return (false, 0, None) }

                let inner_ip_header_len = ((net_layer_data[8] & 0b_0000_1111u8) as usize) * 4;
                if net_layer_data.len() < (16 + inner_ip_header_len) {
                    // 如果存在内层ipv4数据包, 网络层的总长度应至少为 外层icmp报头(8字节) + 内层ipv4报头 + 内层icmp报头(8字节)
                    return (false, 0, None)
                }

                // icmp_v4 首部占8个字节, 后移8个字节, 取出内部的ipv4报文
                let inner_ipv4 = &net_layer_data[8..];

                // 取出内部ipv4数据包中包含的 tcp 报文
                let inner_tcp = &inner_ipv4[inner_ip_header_len..];

                // 取出内部数据包中的地址信息
                let inner_src_ip  = Ipv4PacketU32::get_source_addr(inner_ipv4);
                let inner_dest_ip = Ipv4PacketU32::get_dest_addr(inner_ipv4);

                let inner_sport = ((inner_tcp[0] as u16) << 8) | (inner_tcp[1] as u16);

                // 使用icmp错误信息中包含的ipv4首部重新生成验证信息
                let validation = aes_rand.validate_gen_v4_u32(
                    inner_src_ip, inner_dest_ip, &inner_tcp[2..4]);

                {
                    let local_sport_index = ((validation[0] as usize) << 8) | (validation[1] as usize);
                    let local_sport = self.sports[ local_sport_index % self.sports_len ];

                    // 如果 接收到的数据包的 目的端口, 与本机对应的源端口一致
                    // 注意: icmp协议返回的端口号为 0
                    if inner_sport == local_sport { (true, 0, Some(inner_dest_ip)) } else { (false, 0, None) }
                }

            }
            _ => return (false, 0, None)
        }
    }


    fn print_header(&self) -> Vec<String> {
        let mut output_data = Vec::with_capacity(self.fields_flag.len);
        push_fields_name!(self; output_data;
            source_addr, sport,
            dport, sequence_num, ack_num, window_size,
            icmp_responder, icmp_type, icmp_code, icmp_unreach,
            classification);

        if self.print_ipv4_packet {
            output_data.extend(Ipv4PacketU32::print_header());
        }
        
        output_data
    }

    fn process_packet_v4(&self, _header: &PacketHeader, _data_link_header: &[u8], ipv4_header: &Ipv4PacketU32, net_layer_data: &[u8], inner_ip: Option<u32>) -> (bool,Vec<String>) {

        match ipv4_header.protocol {
            6 => {
                let mut output_data = Vec::with_capacity(self.fields_flag.len);
                push_fields_val!(self; output_data; (source_addr, Ipv4Addr::from(ipv4_header.source_addr)));

                let rst;
                if self.fields_flag.tcp_fields_exist {
                    let tcp_header = TcpPacket::from(net_layer_data);
                    rst = tcp_header.rst == 1;

                    push_fields_val!(self; output_data; (sport, tcp_header.sport), (dport, tcp_header.dport),
                     (sequence_num, tcp_header.sequence_num), (ack_num, tcp_header.ack_num), (window_size, tcp_header.window_size));

                } else {
                    rst = ((net_layer_data[13] >> 2) & 1) == 1;
                    if self.fields_flag.sport {
                        let sport = ((net_layer_data[0] as u16) << 8) | (net_layer_data[1] as u16);
                        output_data.push(sport.to_string());
                    }
                }

                push_fields_val!(self; output_data;
                        (icmp_responder, ""),
                        (icmp_type, ""),
                        (icmp_code, ""),
                        (icmp_unreach, ""));

                if self.fields_flag.classification {
                    if rst {
                        output_data.push(String::from("rst"));
                    } else {
                        output_data.push(String::from("syn_ack"));
                    }
                }

                if self.print_ipv4_packet {
                    output_data.extend(ipv4_header.print())
                }
                
                (!rst, output_data)
            }

            1 => {
                let mut output_data = Vec::with_capacity(self.fields_flag.len);

                if let Some(inner_dest_ip) = inner_ip {
                    push_fields_val!(self; output_data; (source_addr, Ipv4Addr::from(inner_dest_ip)));
                } else {
                    push_fields_val!(self; output_data; (source_addr, ""));
                }

                if self.fields_flag.tcp_fields_exist {
                    push_fields_val!(self; output_data; (sport, ""), (dport, ""),
                    (sequence_num, ""), (ack_num, ""), (window_size, ""));
                }

                push_fields_val!(self; output_data;
                        (icmp_responder, ipv4_header.source_addr),
                        (icmp_type, net_layer_data[0]),
                        (icmp_code, net_layer_data[1]));

                if self.fields_flag.icmp_unreach {
                    let icmp_code = net_layer_data[1] as usize;
                    if icmp_code <= 15 {
                        output_data.push(ICMP_UNREACH[icmp_code].to_string());
                    } else {
                        output_data.push(String::new());
                    }
                }

                push_fields_val!(self; output_data; (classification, "icmp"));

                if self.print_ipv4_packet {
                    output_data.extend(ipv4_header.print())
                }

                (false, output_data)
            }

            _ => (false, vec![])
        }
    }
}