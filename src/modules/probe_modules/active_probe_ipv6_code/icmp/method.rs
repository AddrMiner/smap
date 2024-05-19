use crate::modules::probe_modules::active_probe_ipv6_code::CodeProbeMethodV6;
use crate::modules::probe_modules::active_probe_ipv6_code::icmp::CodeIcmpEchoV6;
use crate::modules::probe_modules::tools::ethernet::make_ethernet_header;
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;
use crate::tools::net_handle::packet::v6::icmp_v6::IcmpV6Packet;
use crate::tools::net_handle::packet::v6::packet_v6_u128::Ipv6PacketU128;

impl CodeProbeMethodV6 for CodeIcmpEchoV6 {
    fn thread_initialize_v6(&mut self, local_mac: &MacAddress, gateway_mac: &MacAddress) {
        //  填充以太网首部字段 14字节       以太网类型为 ipv6 在以太网类型字段中的标识
        make_ethernet_header(&mut self.base_buf, local_mac, gateway_mac, 0x86DDu16);

        // 填充不连地址的ipv6首部字段  8字节
        self.base_buf.extend(Ipv6PacketU128 {
            traffic_class: 0,
            flow_label: 0,

            payload_len: self.net_layer_data_len,             // 负载长度  icmp_v6首部(8字节) + 4字节验证数据 + 编码(负载长度)
            next_header: 58,             // 下一首部指向icmp_v6协议
            hop_limit: 64,              // 设置初始ttl

            // 这两项无效, 同时也不会传入
            source_addr: 0,
            dest_addr: 0,
        }.get_u8_vec_without_addr());
    }

    fn make_packet_v6(&self, source_ip: u128, dest_ip: u128, code: Vec<u8>, aes_rand: &AesRand) -> Vec<u8> {
        // 按最大数据包长度设置 向量容量
        let mut packet = Vec::with_capacity(self.total_len);

        let source_ip_bytes = source_ip.to_be_bytes();
        let dest_ip_bytes = dest_ip.to_be_bytes();

        // 以太网 和 ipv6首部填充
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
        
        //println!("有效载荷长度: {}\n code_len:{}\n total_len:{}", u16::from_be_bytes([packet[18], packet[19]]), code.len(), total_len);

        {
            // icmp报头: [ 类型: {54}  代码: {55}  校验和: {56, 57} id: {58, 59} 序列号: {60, 61} ]
            // icmp数据: [ 62 .. <总长度]

            // icmp数据: [ 验证数据: {62, 63, 64, 65}, 编码: {66 .. } ]

            // 生成验证信息, 注意这里是 源地址在前
            let validation = aes_rand.validate_gen_v6_u128_without_sport(source_ip, dest_ip);

            // 写入icmp_v6首部
            packet.extend([
                //        类型              code                      check_sum字段填充为0
                128,               0,                  0,                  0,
                // 使用验证数据的 第10, 11位(大端字节)作为id                       序列号填充为0
                validation[10],  validation[11],                  0,                  0,
            ]);

            // 使用验证数据的 前4字节 作为icmp_v6的 数据部分前四字节
            packet.extend_from_slice(&validation[0..4]);
            
            // 将 区域编码 编码为 icmp_v6数据部分的后n个字节
            packet.extend(code);

            let check_sum_bytes = IcmpV6Packet::get_check_sum(&source_ip_bytes, &dest_ip_bytes,
                                                              // len: 8字节(icmp首部) + 4字节(验证数据) + n字节(区域编码)
                                                              self.net_layer_data_len as u32, &packet[54..self.total_len]);
            packet[56] = check_sum_bytes[0];
            packet[57] = check_sum_bytes[1];
        }
        packet
    }

    fn receive_packet_v6(&self, net_layer_header: &[u8], net_layer_data:&[u8], aes_rand: &AesRand) -> Option<(u128, Vec<u8>)> {
        
        // 判断是否为icmp协议, 回应报文
        if net_layer_header[6] != 58 || net_layer_data[0] != 129 { return None }
        
        // 提取数据包的长度字段, 如果低于 icmp_v6首部(8字节) + 4字节验证数据 + 编码(负载长度)
        let payload_len = ((net_layer_header[4] as u16) << 8) | (net_layer_header[5] as u16);
        if payload_len < self.net_layer_data_len { return None }
        
        
        let source_addr = u128::from_be_bytes([net_layer_header[8], net_layer_header[9], net_layer_header[10], net_layer_header[11],
                                                            net_layer_header[12], net_layer_header[13], net_layer_header[14], net_layer_header[15],
                                                            net_layer_header[16], net_layer_header[17], net_layer_header[18], net_layer_header[19],
                                                            net_layer_header[20], net_layer_header[21], net_layer_header[22], net_layer_header[23]]);
        
        let dest_addr =  u128::from_be_bytes([net_layer_header[24], net_layer_header[25], net_layer_header[26], net_layer_header[27],
                                                            net_layer_header[28], net_layer_header[29], net_layer_header[30], net_layer_header[31],
                                                            net_layer_header[32], net_layer_header[33], net_layer_header[34], net_layer_header[35],
                                                            net_layer_header[36], net_layer_header[37], net_layer_header[38], net_layer_header[39], ]);
        

        // 使用目的地址, 源地址 生成验证信息, 注意不包含 源端口
        let validation = aes_rand.validate_gen_v6_u128_without_sport(dest_addr, source_addr);

        // id 字段是由 验证信息的第10, 11位生成的
        if net_layer_data[4] != validation[10] || net_layer_data[5] != validation[11] { return None }

        let icmp6_val_data = &net_layer_data[8..12];
        if !icmp6_val_data.eq(&validation[0..4]) { return None }
        
        // 从数据包中 提取 区域编码
        Some((source_addr, net_layer_data[12..].into()))
    }
} 