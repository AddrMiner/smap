use std::net::Ipv6Addr;
use chrono::Utc;
use libc::timeval;
use crate::modules::probe_modules::tools::ethernet::make_ethernet_header;
use crate::modules::probe_modules::topology_probe::tools::default_ttl::get_default_ttl;
use crate::modules::probe_modules::topology_probe::tools::others::get_dest_port;
use crate::modules::probe_modules::topology_probe::topo_mod_v6::{TopoMethodV6, TopoResultV6};
use crate::modules::probe_modules::topology_probe::v6::topo_tcp::TopoTcpV6;
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;
use crate::tools::net_handle::packet::tcp::TcpPacket;
use crate::tools::net_handle::packet::v6::packet_v6_u128::Ipv6PacketU128;

impl TopoMethodV6 for TopoTcpV6 {
    fn thread_initialize_v6(&mut self, local_mac: &MacAddress, gateway_mac: &MacAddress) {
        //  填充以太网首部字段 14字节       以太网类型为 ipv6 在以太网类型字段中的标识
        make_ethernet_header(&mut self.base_buf, local_mac, gateway_mac,0x86DDu16);

        // 填充不连地址的ipv6首部字段  8字节
        self.base_buf.extend(Ipv6PacketU128 {
            traffic_class: 0,
            flow_label: 0,

            payload_len: 20,             // 负载长度  tcp首部(20字节)
            next_header: 6,             // 下一首部指向 tcp协议
            hop_limit: 64,              // 设置初始ttl

            // 这两项无效, 同时也不会传入
            source_addr: 0,
            dest_addr: 0,
        }.get_u8_vec_without_addr());

        // 获取 tcp首部序列号之后的部分, 注意包含check_sum且check_sum为0    12字节
        self.tcp_header_after_seq.extend(TcpPacket {
            // 以下三项无效, 也不会传入
            sport: 0,
            dport: 0,
            sequence_num: 0,

            ack_num: 0,
            header_len: 5,      // 5 * 4 = 20字节
            urg: 0,
            ack: if self.use_ack { 1 } else { 0 },      // 根据用户指定， 选择使用 syn 或 syn_ack
            psh: 0,
            rst: 0,
            syn: 1,
            fin: 0,
            window_size: 2048,
            check_sum: 0,           // 该项无效, 获取字节数组时将被自动设置为 0
            urgent_pointer: 0,
        }.get_u8_vec_after_sequence());
    }

    fn make_packet_v6(&self, source_ip: u128, dest_ip: u128, dest_port_offset:Option<u16>, hop_limit: u8, aes_rand: &AesRand) -> Vec<u8> {
        // 以太网首部(14字节) + ipv6首部(40字节) + tcp首部(20字节) = 74
        let mut packet = Vec::with_capacity(74);

        let source_ip_bytes = source_ip.to_be_bytes();
        let dest_ip_bytes = dest_ip.to_be_bytes();
        {
            // 以太网报头: [ 目的地址: { 0, 1, 2, 3, 4, 5}  源地址: { 6, 7, 8, 9, 10, 11 }  标识 { 12, 13 } ]
            // ipv6 报头: [ 版本: {14(1111_0000), 通信分类: {14(0000_1111), 15(1111_0000)}, 流标签:{15(0000_1111), 16, 17} ]
            //           [ 有效载荷长度: {18, 19}    下一头部: {20}   跳数限制: {21} ]
            //           [ 源地址:  { 22, 23, 24, 25,     26, 27, 28, 29,      30, 31, 32, 33,   34, 35, 36, 37 } ]
            //           [ 目的地址:{ 38, 39, 40, 41,     42, 43, 44, 45,      46, 47, 48, 49,   50, 51, 52, 53 } ]

            // 写入 以太网首部, 不含地址的 ipv6首部
            packet.extend_from_slice(&self.base_buf);

            // 写入 跳数限制
            packet[21] = hop_limit;

            // 写入 ipv6源地址
            packet.extend(source_ip_bytes);

            // 写入 ipv6目的地址
            packet.extend(dest_ip_bytes);
        }

        let validation = aes_rand.validate_gen_v6_u128_without_sport(source_ip, dest_ip);
        {
            // tcp 报头: [ 源端口: {54, 55}   目的端口: {56, 57} ]
            //          [ 序列号: {58, 59, 60, 61} ]      注意: 序列号第一字节为原始TTL, 剩余三个字节为 后24位的时间戳
            //          [ 确认号: {62, 63, 64, 65} ]
            //          [ 数据偏移: {66(1111_0000)}  保留字段:{66(0000_1111), 67(11_000000)} 标记字段:{67(00_111111)} 窗口:{68, 69} ]
            //          [ 校验和: {70, 71} 紧急指针{72, 73} ]

            // 写入 源端口 (2字节)
            {   // 下标为 0..len-1(最大为65535),  以 验证字段前两个字节 作为随机索引, 从源端口向量中提取源端口
                let sport_index = ((validation[0] as usize) << 8) | (validation[1] as usize);
                let sport = self.tcp_sports[ sport_index % self.tcp_sports_len ];
                packet.extend(sport.to_be_bytes());
            }

            // 写入 目标端口 (2字节)
            let dest_port = dest_port_offset.map_or(self.default_dest_port,
                                                    |offset|{ get_dest_port(self.default_dest_port, offset) }).to_be_bytes();
            packet.extend(dest_port);

            // 将 序列号第1字节 设为 原始跳数限制
            packet.push(hop_limit);
            
            if self.use_time_encoding {
                // 获得当前时间戳的 后24位
                let send_time = Utc::now().timestamp_millis();
                let send_time = ((send_time & 0xff_ffff) as u32).to_le_bytes();
                
                packet.extend_from_slice(&send_time[0..3]);
            } else {
                // 将验证数据的 前3字节 作为 序列号后3字节
                packet.extend_from_slice(&validation[0..3]);
            }
            
            // 写入 tcp首部 序列号以后的部分 (12字节)
            packet.extend_from_slice(&self.tcp_header_after_seq);

            let tcp_check_sum_bytes = TcpPacket::get_check_sum_v6(&source_ip_bytes, &dest_ip_bytes, 20, &packet[54..74]);
            packet[70] = tcp_check_sum_bytes[0]; packet[71] = tcp_check_sum_bytes[1];
        }
        packet
    }

    fn parse_packet_v6(&self, ts: &timeval, ipv6_header: &[u8], net_layer_data: &[u8], aes_rand: &AesRand) -> Option<TopoResultV6> {
        // ip报头协议字段必须为 icmp
        // 如果存在内层数据包, 网络层应至少包含  外层icmp(8字节) + 内层ipv6报头(40字节) + 内层tcp报头(20字节) = 68
        if ipv6_header[6] != 58 || net_layer_data.len() < 68 { return None }

        // 是否是来自 目的地址 或 目标网络(主机不可达消息) 的响应
        let from_destination= match net_layer_data[0] {
            // 如果 ICMP类型字段 为 目标不可达
            1 => {
                match net_layer_data[1] {
                    // 端口不可达
                    4 => true,
                    // 主机不可达
                    3 => if self.allow_tar_network_respond { true } else { return None },
                    _ => return None,
                }
            }
            // 生存时间为0(code:0) 或 分片重组超时(code:1)
            3 => match net_layer_data[1] {
                0 => false,
                _ => return None,
            },
            _ => return None,
        };

        // icmp_v6 首部占8个字节, 后移8个字节, 取出内部的ipv6报文
        let inner_ipv6 = &net_layer_data[8..];
        let inner_tcp_header_data = &inner_ipv6[40..];

        // 取出内部数据包中的地址信息
        let inner_src_ip  = Ipv6PacketU128::get_source_addr(inner_ipv6);
        let inner_dest_ip = Ipv6PacketU128::get_dest_addr(inner_ipv6);

        {
            // 生成验证信息
            let validation = aes_rand.validate_gen_v6_u128_without_sport(inner_src_ip, inner_dest_ip);

            let sport = ((inner_tcp_header_data[0] as u16) << 8) | (inner_tcp_header_data[1] as u16);
            let local_sport;
            {   // 使用 验证信息还原 发送时使用的源端口, 目标端口参与验证信息计算, 因此不需要单独检验
                let local_sport_index = ((validation[0] as usize) << 8) | (validation[1] as usize);
                local_sport = self.tcp_sports[local_sport_index % self.tcp_sports_len];
            }
            // 检查 源端口
            if local_sport != sport { return None }
        }

        // 提取 数据包 的 源ip
        let src_ip = Ipv6PacketU128::get_source_addr(ipv6_header);

        // 提取 发送时 的 ttl      注意:编码原始ttl的位置在 序列号第1字节
        let original_ttl = inner_tcp_header_data[4];

        // 计算距离
        let distance = if from_destination { original_ttl - inner_ipv6[7] + 1 } else { original_ttl };

        // 计算 经过的时间
        let spent_time = if self.use_time_encoding {

            // 提取 发送时的 时间戳
            let ori_time_bytes:[u8;4] = [inner_tcp_header_data[5], inner_tcp_header_data[6], inner_tcp_header_data[7], 0];
            let original_time = u32::from_le_bytes(ori_time_bytes);

            // 此处注意严格检查
            let now_time = ((ts.tv_sec as u64) * 1000) + ((ts.tv_usec as u64) / 1000);
            // 提取 毫秒时间戳 的最后24比特
            let now_time = (now_time & 0xff_ffff) as u32;

            // 计算 经过时间
            now_time - original_time
        } else { 0 };
        
        Some(
            TopoResultV6 {
                dest_ip: inner_dest_ip,
                responder: src_ip,
                distance,
                from_destination,
                rtt: spent_time as u64,
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

    fn print_record(&self, res: &TopoResultV6, ipv6_header: &[u8]) -> Vec<String> {
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

