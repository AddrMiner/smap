use std::net;
use pcap::PacketHeader;
use net::Ipv6Addr;
use crate::modules::probe_modules::probe_mod_v6::ProbeMethodV6;
use crate::modules::probe_modules::tools::ethernet::make_ethernet_header;
use crate::{push_fields_name, push_fields_val};
use crate::modules::probe_modules::v6::tcp::tcp_syn_opt::TcpSynOptV6;
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;
use crate::tools::net_handle::packet::tcp::opt::opt_fields::TcpOptFields;
use crate::tools::net_handle::packet::tcp::TcpPacket;
use crate::tools::net_handle::packet::v6::packet_v6_u128::Ipv6PacketU128;

impl ProbeMethodV6 for TcpSynOptV6 {
    fn thread_initialize_v6(&mut self, local_mac: &MacAddress, gateway_mac: &MacAddress) {
        //  填充以太网首部字段 14字节       以太网类型为 ipv6 在以太网类型字段中的标识
        make_ethernet_header(&mut self.base_buf, local_mac, gateway_mac,0x86dd);

        // 填充不包含地址的ipv6首部字段  8字节
        self.base_buf.extend(Ipv6PacketU128 {
            traffic_class: 0,
            flow_label: 0,

            payload_len: self.tcp_len as u16,             // 负载长度  除了基本首部以外的字节数（所有扩展首部字节数都算在内） tcp首部 + 负载
            next_header: 6,                               // 下一首部指向 tcp 协议
            hop_limit: 64,                                // 设置 初始ttl

            // 这两项无效, 同时也不会传入
            source_addr: 0,
            dest_addr: 0,
        }.get_u8_vec_without_addr());

        // 获取 tcp首部序列号之后的部分, 注意包含check_sum    12字节
        self.tcp_header_after_seq.extend(TcpPacket {
            // 以下三项无效, 也不会传入
            sport: 0,
            dport: 0,
            sequence_num: 0,

            ack_num: 0,
            header_len: 5 + ((self.opt_payload.len() / 4) as u8),
            urg: 0,
            ack: 0,
            psh: 0,
            rst: 0,
            syn: 1,
            fin: 0,
            window_size: 65535,
            check_sum: 0,           // 该项无效, 获取字节数组时将被自动设置为 0
            urgent_pointer: 0,
        }.get_u8_vec_after_sequence());
    }

    fn make_packet_v6(&self, source_ip: u128, dest_ip: u128, dest_port: u16, hop_limit: Option<u8>, aes_rand: &AesRand) -> Vec<u8> {
        // 按最大数据包长度设置 向量容量
        let mut packet = Vec::with_capacity(self.max_len);

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

            if let Some(h) = hop_limit { packet[21] = h; }

            // 写入 ipv6源地址
            packet.extend(source_ip_bytes);

            // 写入 ipv6目的地址
            packet.extend(dest_ip_bytes);
        }

        let validation = aes_rand.validate_gen_v6_u128(source_ip, dest_ip, &dest_port.to_be_bytes());
        {
            // tcp 报头: [ 源端口: {54, 55}   目的端口: {56, 57} ]
            //          [ 序列号: {58, 59, 60, 61} ]
            //          [ 确认号: {62, 63, 64, 65} ]
            //          [ 数据偏移: {66(1111_0000)}  保留字段:{66(0000_1111), 67(11_000000)} 标记字段:{67(00_111111)} 窗口:{68, 69} ]
            //          [ 校验和: {70, 71} 紧急指针{72, 73} ]
            // tcp 选项: [ 负载: {74, <总长度} ]

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

            let tcp_check_sum_bytes = TcpPacket::get_check_sum_v6(&source_ip_bytes, &dest_ip_bytes, self.tcp_len, &packet[54..self.max_len]);
            packet[70] = tcp_check_sum_bytes[0];
            packet[71] = tcp_check_sum_bytes[1];
        }
        packet
    }

    fn is_successful(&self, _data_link_header:&[u8], ipv6_header:&Ipv6PacketU128, net_layer_data:&[u8], aes_rand:&AesRand) -> bool {
        if ipv6_header.next_header != 6 || net_layer_data.len() < 20 || ((net_layer_data[13] >> 2) & 1) == 1 { return false }

        let validation = aes_rand.validate_gen_v6_u128(ipv6_header.dest_addr, ipv6_header.source_addr, &net_layer_data[0..2]);
        {   // 判断 接收到的数据包的 目的端口(本机源端口) 是否 正确
            // 数据包的 源端口(探测的目标端口), 已在 验证字段 中进行检查, 验证字段的输入为 三元组(源地址, 目的地址, 目的端口)
            let dport = ((net_layer_data[2] as u16) << 8) | (net_layer_data[3] as u16);

            let local_sport_index = ((validation[0] as usize) << 8) | (validation[1] as usize);
            let local_sport = self.sports[ local_sport_index % self.sports_len ];

            if dport != local_sport { return false }
        }

        let sent_seq = u32::from_be_bytes([validation[0], validation[1], validation[2], validation[3]]);
        let ack = u32::from_be_bytes([net_layer_data[8], net_layer_data[9], net_layer_data[10], net_layer_data[11]]);
        ack == (sent_seq + 1)
    }

    fn validate_packet_v6(&self, _data_link_header: &[u8], ipv6_header: &Ipv6PacketU128, net_layer_data: &[u8], aes_rand: &AesRand) -> (bool, u16, Option<u128>) {
        if ipv6_header.next_header != 6 || net_layer_data.len() < 20 {
            // 如果ipv6首部中的 下一首部 字段不是 6(tcp), 返回 验证失败
            // 网络层数据必须至少为 20字节(tcp首部)

            return (false, 0, None)
        }

        let validation = aes_rand.validate_gen_v6_u128(ipv6_header.dest_addr, ipv6_header.source_addr, &net_layer_data[0..2]);
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

    fn process_packet_v6(&self, _header: &PacketHeader, _data_link_header: &[u8], ipv6_header: &Ipv6PacketU128, net_layer_data: &[u8], _inner_ip: Option<u128>) -> (bool, Vec<String>) {
        let mut output_data = Vec::with_capacity(self.fields_flag.len);
        push_fields_val!(self; output_data; (source_addr, Ipv6Addr::from(ipv6_header.source_addr)));

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