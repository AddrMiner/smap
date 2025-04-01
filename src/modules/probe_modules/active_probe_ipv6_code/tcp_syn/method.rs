use std::process::exit;
use log::error;
use crate::modules::probe_modules::active_probe_ipv6_code::CodeProbeMethodV6;
use crate::modules::probe_modules::active_probe_ipv6_code::tcp_syn::CodeTcpSynScanV6;
use crate::modules::probe_modules::tools::ethernet::make_ethernet_header;
use crate::SYS;
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;
use crate::tools::net_handle::packet::tcp::TcpPacket;
use crate::tools::net_handle::packet::v6::packet_v6_u128::Ipv6PacketU128;

impl CodeProbeMethodV6 for CodeTcpSynScanV6 {
    fn thread_initialize_v6(&mut self, local_mac: &MacAddress, gateway_mac: &MacAddress) {
        //  填充以太网首部字段 14字节       以太网类型为 ipv6 在以太网类型字段中的标识
        make_ethernet_header(&mut self.base_buf, local_mac, gateway_mac,0x86dd);

        // 填充不包含地址的ipv6首部字段  8字节
        self.base_buf.extend(Ipv6PacketU128 {
            traffic_class: 0,
            flow_label: 0,

            payload_len: 20,            // 负载长度    tcp基本首部(20字节)
            next_header: 6,             // 下一首部指向  tcp 协议
            hop_limit: 64,              // 设置 初始ttl

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

    fn make_packet_v6(&self, source_ip: u128, dest_ip: u128, dest_port: u16, code: Vec<u8>, aes_rand: &AesRand) -> Vec<u8> {
        if code.len() != 4 {
            // 编码长度必须为4字节
            error!("{}", SYS.get_info("err", "code_len_4"));
            exit(1)
        }

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

            // 写入 源端口 (2字节)
            {   // 下标为 0..len-1(最大为65535),  以 验证字段前两个字节 作为随机索引, 从源端口向量中提取源端口
                let sport_index = ((validation[0] as usize) << 8) | (validation[1] as usize);
                let sport = self.sports[ sport_index % self.sports_len ];
                packet.extend(sport.to_be_bytes());
            }

            // 写入 目标端口 (2字节)
            packet.extend(dest_port.to_be_bytes());

            // 写入 序列号 (4字节)   此处为自定义编码
            // 警告: 自定义编码必须为4字节
            packet.extend(code);

            // 写入 tcp首部 序列号以后的部分 (12字节)
            packet.extend_from_slice(&self.tcp_header_after_seq);

            let tcp_check_sum_bytes = TcpPacket::get_check_sum_v6(&source_ip_bytes, &dest_ip_bytes, 20, &packet[54..74]);
            packet[70] = tcp_check_sum_bytes[0];
            packet[71] = tcp_check_sum_bytes[1];
        }
        packet
    }

    fn receive_packet_v6(&self, net_layer_header: &[u8], net_layer_data: &[u8], aes_rand: &AesRand) -> Option<(u128, u16, Vec<u8>)> {
        if net_layer_header[6] != 6 || net_layer_data.len() < 20 || ((net_layer_data[13] >> 2) & 1) == 1 { return None }

        let source_addr = u128::from_be_bytes([net_layer_header[8], net_layer_header[9], net_layer_header[10], net_layer_header[11],
            net_layer_header[12], net_layer_header[13], net_layer_header[14], net_layer_header[15],
            net_layer_header[16], net_layer_header[17], net_layer_header[18], net_layer_header[19],
            net_layer_header[20], net_layer_header[21], net_layer_header[22], net_layer_header[23]]);

        let dest_addr =  u128::from_be_bytes([net_layer_header[24], net_layer_header[25], net_layer_header[26], net_layer_header[27],
            net_layer_header[28], net_layer_header[29], net_layer_header[30], net_layer_header[31],
            net_layer_header[32], net_layer_header[33], net_layer_header[34], net_layer_header[35],
            net_layer_header[36], net_layer_header[37], net_layer_header[38], net_layer_header[39], ]);
        
        let validation = aes_rand.validate_gen_v6_u128(dest_addr, source_addr, &net_layer_data[0..2]);
        {   // 判断 接收到的数据包的 目的端口(本机源端口) 是否 正确
            // 数据包的 源端口(探测的目标端口), 已在 验证字段 中进行检查, 验证字段的输入为 三元组(源地址, 目的地址, 目的端口)
            let dport = ((net_layer_data[2] as u16) << 8) | (net_layer_data[3] as u16);

            let local_sport_index = ((validation[0] as usize) << 8) | (validation[1] as usize);
            let local_sport = self.sports[ local_sport_index % self.sports_len ];

            if dport != local_sport { return None }
        }
        
        let ack = u32::from_be_bytes([net_layer_data[8], net_layer_data[9], net_layer_data[10], net_layer_data[11]]);
        if ack == 0 { return None }
        
        let sent_seq = ack - 1;

        let sport = ((net_layer_data[0] as u16) << 8) | (net_layer_data[1] as u16);
        
        // 发送的序列号 转换为 大端字节
        Some((source_addr, sport, sent_seq.to_be_bytes().into()))
    }
}