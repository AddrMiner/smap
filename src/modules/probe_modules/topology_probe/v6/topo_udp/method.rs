use std::net::Ipv6Addr;
use chrono::Utc;
use libc::timeval;
use crate::modules::probe_modules::tools::ethernet::make_ethernet_header;
use crate::modules::probe_modules::topology_probe::tools::default_ttl::get_default_ttl;
use crate::modules::probe_modules::topology_probe::tools::others::get_dest_port;
use crate::modules::probe_modules::topology_probe::topo_mod_v6::{TopoMethodV6, TopoResultV6};
use crate::modules::probe_modules::topology_probe::v6::topo_udp::TopoUdpV6;
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;
use crate::tools::net_handle::packet::udp::UdpPacket;
use crate::tools::net_handle::packet::v6::packet_v6_u128::Ipv6PacketU128;

impl TopoMethodV6 for TopoUdpV6 {
    fn thread_initialize_v6(&mut self, local_mac: &MacAddress, gateway_mac: &MacAddress) {
        //  填充以太网首部字段 14字节       以太网类型为 ipv6 在以太网类型字段中的标识
        make_ethernet_header(&mut self.base_buf, local_mac, gateway_mac,0x86DDu16);

        // 填充在 payload_len 之前的 ipv6首部字段 4字节
        self.base_buf.extend(Ipv6PacketU128 {
            traffic_class: 0,
            flow_label: 0,

            // 以下几项无效
            payload_len: 0,
            next_header: 17,
            hop_limit: 0,
            source_addr: 0,
            dest_addr: 0,
        }.get_u8_vec_before_payload_len());
    }

    fn make_packet_v6(&self, source_ip: u128, dest_ip: u128, dest_port_offset:Option<u16>, code:u8, hop_limit: u8, aes_rand: &AesRand) -> Vec<u8> {

        let validation = aes_rand.validate_gen_v6_u128_without_sport(source_ip, dest_ip);

        // 计算 ipv6数据包的长度  主要目的是 使数据包长度可变, 避免被探查
        // validation[2]的最后四个比特决定 可变长度大小
        let payload_len:u16 = 18 + (validation[2] & 0xf) as u16;
        let payload_len_usize = payload_len as usize;
        let payload_len_be_bytes = payload_len.to_be_bytes();
            
        // 包括 以太网首部 在内的数据包总长度 = 以太网首部(14字节) + ipv6首部(40字节) + ipv6有效载荷长度
        let total_len = 54 + payload_len_usize;

        // 设置 向量容量
        let mut packet = Vec::with_capacity(total_len);

        let source_ip_bytes = source_ip.to_be_bytes();
        let dest_ip_bytes = dest_ip.to_be_bytes();
        {
            // 以太网报头: [ 目的地址: { 0, 1, 2, 3, 4, 5}  源地址: { 6, 7, 8, 9, 10, 11 }  标识 { 12, 13 } ]
            // ipv6 报头: [ 版本: {14(1111_0000), 通信分类: {14(0000_1111), 15(1111_0000)}, 流标签:{15(0000_1111), 16, 17} ]
            //           [ 有效载荷长度: {18, 19}    下一头部: {20}   跳数限制: {21} ]
            //           [ 源地址:  { 22, 23, 24, 25,     26, 27, 28, 29,      30, 31, 32, 33,   34, 35, 36, 37 } ]
            //           [ 目的地址:{ 38, 39, 40, 41,     42, 43, 44, 45,      46, 47, 48, 49,   50, 51, 52, 53 } ]

            // 写入 以太网首部, payload_len前的 ipv6首部
            packet.extend_from_slice(&self.base_buf);

            // 写入 有效载荷长度
            packet.extend_from_slice(&payload_len_be_bytes);
            
            // 写入 下一头部(udp), 跳数限制
            packet.extend([17, hop_limit]);

            // 写入 ipv6源地址
            packet.extend(source_ip_bytes);

            // 写入 ipv6目的地址
            packet.extend(dest_ip_bytes);
        }

        {
            // udp 报头: [源端口: {54, 55}  目的端口: {56, 57}]
            //          [ udp长度: {58, 59}   udp校验和: {60, 61}, udp载荷:{62..(总长度 - 1)}]
            // udp 载荷: [ 初始ttl:{62}, code:{63}, 时间戳(如果有): {64, 65, 66, 67, 68, 69, 70, 71}, 预设载荷: {72 .. < total_len } ]
            // 载荷udp索引:[初始ttl:{8}, code:{9}, 时间戳(如果有): {10..<18} ]

            // 写入 源端口 (2字节)
            {   // 下标为 0..len-1(最大为65535),  以验证字段前两个字节作为随机索引, 从源端口向量中提取源端口
                let sport_index = ((validation[0] as usize) << 8) | (validation[1] as usize);
                let sport = self.udp_sports[ sport_index % self.udp_sports_len ];
                packet.extend(sport.to_be_bytes());
            }

            // 写入 目标端口 (2字节)
            // 如果不存在偏移值, 使用默认的目标端口
            // 如果存在偏移值, 根据偏移值生成新的目标端口
            let dest_port = dest_port_offset.map_or(self.udp_dest_port,
                                                    |offset|{ get_dest_port(self.udp_dest_port, offset) }).to_be_bytes();
            packet.extend(dest_port);

            // 写入 udp长度  
            packet.extend(payload_len_be_bytes);

            // 写入 填充为0的 check_sum字段, 初始ttl, code
            packet.extend([0u8,0, hop_limit, code]);

            // 写入 时间戳 和 填充的udp数据部分
            if self.use_time_encoding {
                // 写入 整个毫秒时间戳
                packet.extend(Utc::now().timestamp_millis().to_be_bytes());
                // 写入 预设载荷  长度为 udp_len - 首部(8字节) - 初始ttl(1字节) - 时间戳(8字节) - code(1字节)
                // 即, 长度为  udp_len - 18字节
                packet.extend_from_slice(&self.udp_payload[..(payload_len_usize - 18)]);
            } else {
                // 写入 预设载荷  长度为 udp_len - 首部(8字节) - 初始ttl(1字节) - code(1字节), 即 udp_len - 10
                packet.extend_from_slice(&self.udp_payload[..(payload_len_usize - 10)]);
            }

            // 计算并写入 udp校验和
            let udp_check_sum_bytes = UdpPacket::get_check_sum_v6(
                &source_ip_bytes, &dest_ip_bytes, payload_len as u32, &packet[54..total_len]);
            packet[60] = udp_check_sum_bytes[0];
            packet[61] = udp_check_sum_bytes[1];
        }
        packet
    }

    fn parse_packet_v6(&self, ts: &timeval, ipv6_header: &[u8], net_layer_packet: &[u8], aes_rand: &AesRand) -> Option<TopoResultV6> {
        // ip报头协议字段必须为 icmp
        // 如果存在内层数据包, 网络层应至少包含  外层icmp(8字节) + 内层ipv6报头(40字节) + 内层udp报头(8字节) + 初始ttl(1字节) + 时间戳(8字节) + code(1字节) = 66
        if ipv6_header[6] != 58 || net_layer_packet.len() < 66 { return None }

        // 是否是来自 目的地址 或 目标网络(主机不可达消息) 的响应
        let from_destination= match net_layer_packet[0] {
            // 如果 ICMP类型字段 为 目标不可达
            1 => {
                match net_layer_packet[1] {
                    // 端口不可达
                    4 => if self.allow_port_unreach { true } else { return None },
                    // 主机不可达
                    3 => if self.allow_tar_network_respond { true } else { return None },
                    _ => return None,
                }
            }
            // 生存时间为0(code:0) 或 分片重组超时(code:1)
            3 => match net_layer_packet[1] {
                0 => false,
                _ => return None,
            },
            _ => return None,
        };

        // icmp_v6 首部占8个字节, 后移8个字节, 取出内部的ipv6报文
        let inner_ipv6 = &net_layer_packet[8..];
        let inner_udp_header_data = &inner_ipv6[40..];

        // 取出内部数据包中的地址信息
        let inner_src_ip  = Ipv6PacketU128::get_source_addr(inner_ipv6);
        let inner_dest_ip = Ipv6PacketU128::get_dest_addr(inner_ipv6);

        // 使用 内层udp源端口 进行校验
        {
            // 生成验证信息
            let validation = aes_rand.validate_gen_v6_u128_without_sport(inner_src_ip, inner_dest_ip);

            let sport = ((inner_udp_header_data[0] as u16) << 8) | (inner_udp_header_data[1] as u16);

            let local_sport;
            {   // 使用 验证信息还原 发送时使用的源端口, 目标端口参与验证信息计算, 因此不需要单独检验
                let local_sport_index = ((validation[0] as usize) << 8) | (validation[1] as usize);
                local_sport = self.udp_sports[local_sport_index % self.udp_sports_len];
            }

            // 检查 源端口
            if local_sport != sport { return None }
        }

        // 提取 数据包 的 源ip
        let src_ip = Ipv6PacketU128::get_source_addr(ipv6_header);

        // 载荷udp索引:[初始ttl:{8}, code:{9}, 时间戳(如果有): {10..<18} ]
        // 提取 发送时 的 ttl
        let original_ttl = inner_udp_header_data[8];

        // 计算距离
        let distance = if from_destination { original_ttl - inner_ipv6[7] + 1 } else { original_ttl };

        // 计算 经过的时间
        let spent_time = if self.use_time_encoding {

            // 提取 发送时的 时间戳
            let ori_time_bytes = &inner_udp_header_data[10..18];
            let original_time = u64::from_be_bytes(ori_time_bytes.try_into().unwrap());
            
            // 此处注意严格检查
            let now_time = ((ts.tv_sec as u64) * 1000) + ((ts.tv_usec as u64) / 1000);

            // 计算 经过时间
            now_time - original_time
        } else { 0 };

        Some(
            TopoResultV6 {
                dest_ip: inner_dest_ip,
                responder: src_ip,
                distance,
                from_destination,
                rtt: spent_time,
                
                code: inner_udp_header_data[9],
            }
        )
    }

    fn print_header(&self) -> Vec<String> {
        let mut output_data = Vec::with_capacity(self.output_len);
        output_data.extend(vec!["dest_ip".to_string(), "responder".to_string(), "distance".to_string()]);

        if self.use_time_encoding { output_data.push("rtt".to_string()); }
        if self.print_default_ttl { output_data.push("default_ttl".to_string()); }
        output_data
    }

    fn print_record(&self, res: &TopoResultV6, ipv6_header:&[u8]) -> Vec<String> {
        let mut output_data = Vec::with_capacity(self.output_len);
        output_data.extend(vec![Ipv6Addr::from(res.dest_ip).to_string(), Ipv6Addr::from(res.responder).to_string(), res.distance.to_string()]);
        
        if self.use_time_encoding { output_data.push(res.rtt.to_string()); }
        if self.print_default_ttl {
            let responder_default_ttl = get_default_ttl(res.distance, ipv6_header[7]);
            output_data.push(responder_default_ttl.to_string());
        } 
        output_data
    }

    fn print_silent_record(&self, dest_ip: u128, distance: u8) -> Vec<String> {
        let mut output_data = Vec::with_capacity(self.output_len);
        output_data.extend(vec![Ipv6Addr::from(dest_ip).to_string(), "null".to_string(), distance.to_string()]);

        if self.use_time_encoding { output_data.push("null".to_string()); }
        if self.print_default_ttl { output_data.push("null".to_string()); }
        output_data
    }
}