use std::net::Ipv4Addr;
use pcap::PacketHeader;
use crate::modules::probe_modules::probe_mod_v4::ProbeMethodV4;
use crate::modules::probe_modules::tools::ethernet::make_ethernet_header;
use crate::{push_fields_name, push_fields_val};
use crate::modules::probe_modules::v4::udp::udp_scan::UdpScanV4;
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;
use crate::tools::net_handle::packet::udp::UdpPacket;
use crate::tools::net_handle::packet::v4::icmp_v4::ICMP_UNREACH;
use crate::tools::net_handle::packet::v4::packet_v4_u32::Ipv4PacketU32;

impl ProbeMethodV4 for UdpScanV4 {
    fn thread_initialize_v4(&mut self, local_mac: &MacAddress, gateway_mac: &MacAddress, rand_u16:u16) {
        //  填充以太网首部字段 14字节       以太网类型为 ipv4 在以太网类型字段中的标识
        make_ethernet_header(&mut self.base_buf, local_mac, gateway_mac, 0x0800u16);

        //  填充没有 地址 的ipv4首部字段  12字节
        self.base_buf.extend(Ipv4PacketU32 {
            ihl: 5,                  // 首部长度为 5 * 4 = 20字节
            tos: 0,                  // 服务类型
            total_len: 20 + (self.udp_len as u16),           // 长度为 ipv4首部(20字节)长度 + udp报文长度

            // 16位标识唯一地标识主机发送的每一个数据报。每发送一个数据报，其值就加1。该值在数据报分片时被复制到每个分片中，因此同一个数据报的所有分片都具有相同的标识值。
            // 警告: 该固定字段可用于识别 扫描流量, 隐秘化扫描应使用随机值
            id: rand_u16,

            rf: 0,
            df: 0,
            mf: 0,
            offset: 0,

            ttl: 64,                 // 初始ttl
            protocol: 17,            // udp 在 ipv4 中的协议号为 17

            // 无论该项输入是什么, 输出字节数组时都会被置为 0
            header_check_sum: 0,
            // 以下几项无效, 不会出现在得到的字节数组中
            source_addr: 0,
            dest_addr: 0,
        }.get_u8_vec_without_addr());
    }

    fn make_packet_v4(&self, source_ip: u32, dest_ip: u32, dest_port: u16, ttl: Option<u8>, aes_rand: &AesRand) -> Vec<u8> {
        // 按最大数据包长度设置 向量容量
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

        // 生成验证信息
        let validation;
        if self.not_check_sport {    // 如果 不对源端口进行检查
            validation = aes_rand.validate_gen_v4_u32_without_sport(source_ip, dest_ip);
        } else {                    // 对源端口进行检查
            validation = aes_rand.validate_gen_v4_u32(source_ip, dest_ip, &dest_port.to_be_bytes());
        }

        {
            // udp 报头: [源端口: {34, 35}  目的端口: {36, 37}]
            //          [ udp长度: {38, 39}   udp校验和: {40, 41}, udp载荷:{42..(总长度 - 1)}]

            // 写入 源端口 (2字节)
            {   // 下标为 0..len-1(最大为65535),  以验证字段前两个字节作为随机索引, 从源端口向量中提取源端口
                let sport_index = ((validation[0] as usize) << 8) | (validation[1] as usize);
                let sport = self.sports[ sport_index % self.sports_len ];
                packet.extend(sport.to_be_bytes());
            }

            // 写入 目标端口 (2字节)
            packet.extend(dest_port.to_be_bytes());

            // 写入 udp长度 和 填充为0的 check_sum字段
            packet.extend_from_slice(&self.udp_len_zero_check_sum_bytes);

            // 写入 udp数据部分
            packet.extend_from_slice(&self.udp_payload);

            // 计算并写入 udp校验和
            let udp_check_sum_bytes = UdpPacket::get_check_sum_v4(
                &source_ip_bytes, &dest_ip_bytes, self.udp_len, &packet[34..self.max_len]);
            packet[40] = udp_check_sum_bytes[0];
            packet[41] = udp_check_sum_bytes[1];
        }
        packet
    }

    fn is_successful(&self, _data_link_header:&[u8], ipv4_header:&Ipv4PacketU32, net_layer_data:&[u8], aes_rand:&AesRand) -> bool {
        if ipv4_header.protocol != 17 || net_layer_data.len() < 8 { return false }

        // 生成验证信息
        let validation;
        if self.not_check_sport {    // 如果 不对源端口进行检查
            validation = aes_rand.validate_gen_v4_u32_without_sport(ipv4_header.dest_addr, ipv4_header.source_addr);
        } else {                    // 对源端口进行检查
            validation = aes_rand.validate_gen_v4_u32(ipv4_header.dest_addr, ipv4_header.source_addr, &net_layer_data[0..2]);
        }

        {   // 判断 接收到的数据包的 目的端口(本机源端口) 是否 正确
            let dport = ((net_layer_data[2] as u16) << 8) | (net_layer_data[3] as u16);

            let local_sport_index = ((validation[0] as usize) << 8) | (validation[1] as usize);
            let local_sport = self.sports[ local_sport_index % self.sports_len ];

            dport == local_sport
        }
    }

    fn validate_packet_v4(&self, _data_link_header: &[u8], ipv4_header: &Ipv4PacketU32, net_layer_data: &[u8], aes_rand: &AesRand) -> (bool, u16, Option<u32>) {

        match ipv4_header.protocol {

            17 => {
                // udp 协议

                // 如果 网络层数据长度 小于 基本首部长度
                if net_layer_data.len() < 8 { return (false, 0, None) }

                // 生成验证信息
                let validation;
                if self.not_check_sport {    // 如果 不对源端口进行检查
                    validation = aes_rand.validate_gen_v4_u32_without_sport(ipv4_header.dest_addr, ipv4_header.source_addr);
                } else {                    // 对源端口进行检查
                    validation = aes_rand.validate_gen_v4_u32(ipv4_header.dest_addr, ipv4_header.source_addr, &net_layer_data[0..2]);
                }

                {   // 判断 接收到的数据包的 目的端口(本机源端口) 是否 正确
                    let dport = ((net_layer_data[2] as u16) << 8) | (net_layer_data[3] as u16);

                    let local_sport_index = ((validation[0] as usize) << 8) | (validation[1] as usize);
                    let local_sport = self.sports[ local_sport_index % self.sports_len ];

                    if dport == local_sport {
                        // 如果 接收到的数据包的 目的端口, 与本机对应的源端口一致
                        (true, u16::from_be_bytes([net_layer_data[0], net_layer_data[1]]), None)
                    } else {
                        (false, 0, None)
                    }
                }
            }

            1 => {
                // icmp_v4 协议
                match net_layer_data[0] {
                    3 | 4 | 5 | 11 => {
                        // 如果icmp类型为 目标不可达, 包过大, 超时, 参数问题中的一种, 即错误类型

                        // 如果存在内层数据包, 网络层应至少包含  外层icmp(8字节) + 内层ipv4报头(20字节) + 内层udp报头(8字节) = 36
                        if net_layer_data.len() < 36 { return (false, 0, None) }

                        let inner_ip_header_len = ((net_layer_data[8] & 0b_0000_1111u8) as usize) * 4;
                        if net_layer_data.len() < (16 + inner_ip_header_len) {
                            // 如果存在内层ipv4数据包, 网络层的总长度应至少为 外层icmp报头(8字节) + 内层ipv4报头 + 内层icmp报头(8字节)
                            return (false, 0, None)
                        }

                        let inner_ipv4 = &net_layer_data[8..];
                        let inner_udp_header_data = &inner_ipv4[inner_ip_header_len..];

                        // 取出内部数据包中的地址信息
                        let inner_src_ip  = Ipv4PacketU32::get_source_addr(inner_ipv4);
                        let inner_dest_ip = Ipv4PacketU32::get_dest_addr(inner_ipv4);

                        // 生成验证信息
                        let validation;
                        if self.not_check_sport {    // 如果 不对源端口进行检查
                            validation = aes_rand.validate_gen_v4_u32_without_sport(inner_src_ip, inner_dest_ip);
                        } else {                    // 对源端口(这里指目标端口)进行检查
                            validation = aes_rand.validate_gen_v4_u32(inner_src_ip, inner_dest_ip, &inner_udp_header_data[2..4]);
                        }

                        let sport = ((inner_udp_header_data[0] as u16) << 8) | (inner_udp_header_data[1] as u16);

                        let local_sport;
                        {   // 使用 验证信息还原 发送时使用的源端口, 目标端口参与验证信息计算, 因此不需要单独检验
                            let local_sport_index = ((validation[0] as usize) << 8) | (validation[1] as usize);
                            local_sport = self.sports[local_sport_index % self.sports_len];
                        }

                        // 注意: icmp协议返回的端口号为 0
                        if local_sport == sport { (true, 0, Some(inner_dest_ip)) } else { (false, 0, None) }
                    }
                    _ => (false, 0, None)
                }
            }
            _ => (false, 0, None)
        }
    }

    fn print_header(&self) -> Vec<String> {
        let mut output_data = Vec::with_capacity(self.fields_flag.len);
        push_fields_name!(self; output_data; source_addr, classification,
            sport, dport,
            icmp_responder, icmp_type, icmp_code, icmp_unreach,
            udp_pkt_size, data);
        output_data
    }

    fn process_packet_v4(&self, _header: &PacketHeader, _data_link_header: &[u8], ipv4_header: &Ipv4PacketU32, net_layer_data: &[u8], inner_ip: Option<u32>) -> (bool, Vec<String>) {
        let mut output_data = Vec::with_capacity(self.fields_flag.len);

        match ipv4_header.protocol {
            17 => {
                // udp协议
                push_fields_val!(self; output_data;
                    (source_addr, Ipv4Addr::from(ipv4_header.source_addr)),

                    (classification, "udp"),

                    (sport, ((net_layer_data[0] as u16) << 8) | (net_layer_data[1] as u16)),
                    (dport, ((net_layer_data[2] as u16) << 8) | (net_layer_data[3] as u16)),

                    (icmp_responder, ""),
                    (icmp_type, ""),
                    (icmp_code, ""),
                    (icmp_unreach, ""),

                    (udp_pkt_size, ((net_layer_data[4] as u16) << 8) | (net_layer_data[5] as u16))
                );

                if self.fields_flag.data {
                    output_data.push(format!("{:?}", &net_layer_data[8..]));
                }
                (true, output_data)
            }
            1 => {
                // icmp_v4
                if let Some(inner_dest_ip) = inner_ip {
                    push_fields_val!(self; output_data; (source_addr, Ipv4Addr::from(inner_dest_ip)));
                } else {
                    push_fields_val!(self; output_data; (source_addr, ""));
                }

                push_fields_val!(self; output_data;
                    (classification, "icmp"),

                    (sport, ""),
                    (dport, ""),

                    (icmp_responder, Ipv4Addr::from(ipv4_header.source_addr)),
                    (icmp_type, net_layer_data[0]),
                    (icmp_code, net_layer_data[1])
                );

                if self.fields_flag.icmp_unreach {
                    if net_layer_data[1] <= 15 {
                        // <= ICMP_UNREACH_PRECEDENCE_CUTOFF
                        output_data.push(ICMP_UNREACH[net_layer_data[1] as usize].to_string());
                    } else {
                        output_data.push("unknown".to_string());
                    }
                }

                push_fields_val!(self; output_data;
                    (udp_pkt_size, ""),
                    (data, "")
                );
                (false, output_data)
            }
            _ => {
                push_fields_val!(self; output_data;
                    (source_addr, Ipv4Addr::from(ipv4_header.source_addr)),
                    (classification, "other"),

                    (sport, ""),
                    (dport, ""),

                    (icmp_responder, ""),
                    (icmp_type, ""),
                    (icmp_code, ""),
                    (icmp_unreach, ""),

                    (udp_pkt_size, ""),
                    (data, "")
                );
                (false, output_data)
            }
        }
    }
}


