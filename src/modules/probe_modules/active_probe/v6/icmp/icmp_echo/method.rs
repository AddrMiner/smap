use std::net::{Ipv6Addr};
use pcap::PacketHeader;
use crate::modules::probe_modules::probe_mod_v6::ProbeMethodV6;
use crate::modules::probe_modules::tools::ethernet::make_ethernet_header;
use crate::{push_fields_name, push_fields_val};
use crate::modules::probe_modules::v6::IcmpEchoV6;
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;
use crate::tools::net_handle::packet::v6::icmp_v6::fields::IcmpV6Fields;
use crate::tools::net_handle::packet::v6::icmp_v6::IcmpV6Packet;
use crate::tools::net_handle::packet::v6::packet_v6_u128::Ipv6PacketU128;

impl ProbeMethodV6 for IcmpEchoV6 {

    /// 在发送线程开始时准备以太网首部, ipv6地址前的首部
    fn thread_initialize_v6(&mut self, local_mac: &MacAddress, gateway_mac: &MacAddress) {

        //  填充以太网首部字段 14字节       以太网类型为 ipv6 在以太网类型字段中的标识
        make_ethernet_header(&mut self.base_buf, local_mac, gateway_mac, 0x86DDu16);

        // 填充不连地址的ipv6首部字段  8字节
        self.base_buf.extend(Ipv6PacketU128 {
            traffic_class: 0,
            flow_label: 0,

            payload_len: 16,             // 负载长度  icmp_v6首部(8字节) + 8字节验证数据
            next_header: 58,             // 下一首部指向icmp_v6协议
            hop_limit: 64,              // 设置初始ttl

            // 这两项无效, 同时也不会传入
            source_addr: 0,
            dest_addr: 0,
        }.get_u8_vec_without_addr());
    }

    /// 发送线程 制作数据包
    fn make_packet_v6(&self, source_ip: u128, dest_ip: u128, _dest_port: u16, hop_limit:Option<u8>, aes_rand:&AesRand) -> Vec<u8> {
        // 按最大数据包长度设置 向量容量
        let mut packet = Vec::with_capacity(70);

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

            if let Some(h) = hop_limit { packet[21] = h; }

            // 写入 ipv6源地址
            packet.extend(source_ip_bytes);

            // 写入 ipv6目的地址
            packet.extend(dest_ip_bytes);
        }

        {
            // icmp报头: [ 类型: {54}  代码: {55}  校验和: {56, 57} id: {58, 59} 序列号: {60, 61} ]
            // icmp数据: [ 62 .. <总长度]

            // icmp数据: [ 62, 63, 64, 65,  66, 67, 68, 69]
            
            // 生成验证信息, 注意这里是 源地址在前
            let validation = aes_rand.validate_gen_v6_u128_without_sport(source_ip, dest_ip);

            // 写入icmp_v6首部
            packet.extend([
                //        类型              code                      check_sum字段填充为0
                           128,               0,                  0,                  0,
                // 使用验证数据的 第10, 11位(大端字节)作为id                       序列号填充为0
                validation[10],  validation[11],                  0,                  0,
            ]);

            // 使用验证数据的 前8字节 作为icmp_v6的数据部分
            packet.extend_from_slice(&validation[0..8]);

            let check_sum_bytes = IcmpV6Packet::get_check_sum(&source_ip_bytes, &dest_ip_bytes,
                                                        // len: 8字节(icmp首部) + 8字节(验证数据)
                                                        16, &packet[54..70]);
            packet[56] = check_sum_bytes[0];
            packet[57] = check_sum_bytes[1];
        }
        packet
    }

    fn is_successful(&self, _data_link_header:&[u8], ipv6_header:&Ipv6PacketU128, net_layer_data:&[u8], aes_rand:&AesRand) -> bool {

        if ipv6_header.next_header != 58 || net_layer_data.len() < 16 || net_layer_data[0] < 128 { return false }

        // 使用目的地址, 源地址 生成验证信息, 注意不包含 源端口
        let validation = aes_rand.validate_gen_v6_u128_without_sport(
            ipv6_header.dest_addr, ipv6_header.source_addr);

        // id 字段是由 验证信息的第10, 11位生成的
        if net_layer_data[4] != validation[10] || net_layer_data[5] != validation[11] {
            // 如果有一个字节不相等, 直接返回false, 否则进行后续判断
            return false
        }

        let icmp6_data = &net_layer_data[8..16];
        icmp6_data.eq(&validation[0..8])
    }

    fn validate_packet_v6(&self, _data_link_header: &[u8], ipv6_header: &Ipv6PacketU128,
                          net_layer_data: &[u8], aes_rand:&AesRand) -> (bool, u16, Option<u128>) {

        if ipv6_header.next_header != 58 || net_layer_data.len() < 16 {
            // 如果ipv6首部中的 下一首部 字段不是 58(icmp v6), 返回 验证失败
            // 网络层数据必须为 16字节(icmp首部8字节, 数据8字节)及以上

            // 注意: 无论是内层源地址, 还是外层源地址, 都只有在验证通过时有效
            return (false, 0, None)
        }

        let icmp6_data;
        match net_layer_data[0] {

            1 | 2 | 3 | 4 => {
                // 如果icmp类型为 目标不可达, 包过大, 超时, 参数问题中的一种, 即错误类型

                if net_layer_data.len() < 64 {
                    // 如果存在 内部ipv6数据包, 则整个网络层的长度至少为  外层icmp报头(8字节) + 内层ipv6报头(40字节) + 内层icmp报头(8字节) + icmp数据(8字节)
                    // 注意: ICMPv6错误报文会尽量包含更多的原始数据报内容, 但不能使得ICMPv6错误报文自身的大小超过IPv6最小的MTU
                    // 8 + 40 + 8 + 8 = 64
                    return (false, 0, None)
                }

                // icmp_v6 首部占8个字节, 后移8个字节, 取出内部的ipv6报文
                let inner_ipv6 = &net_layer_data[8..];

                // 取出内部ipv6数据包中包含的icmp_v6报文
                let inner_icmp6 = &inner_ipv6[40..];

                // 取出内部数据包中的地址信息
                let inner_src_ip  = Ipv6PacketU128::get_source_addr(inner_ipv6);
                let inner_dest_ip = Ipv6PacketU128::get_dest_addr(inner_ipv6);

                // 使用icmp错误信息中包含的ipv6首部重新生成验证信息, 由于源端口为0, 所以不需要加入端口验证
                let validation = aes_rand.validate_gen_v6_u128_without_sport(
                    inner_src_ip, inner_dest_ip);

                // 使用生成的验证信息进行验证
                // id 字段是由 验证信息的第10, 11位生成的
                if inner_icmp6[4] != validation[10] || inner_icmp6[5] != validation[11] {
                    // 如果有一个字节不相等, 直接返回false, 否则进行后续判断
                    return (false, 0, None)
                }

                icmp6_data = &inner_icmp6[8..16];
                if icmp6_data.eq(&validation[0..8]) {
                    // 数据部分匹配通过

                    // 返回内层ip  注意: 这里是内层数据包中的目的地址
                    (true, 0, Some(inner_dest_ip))
                } else {
                    // 数据部分无法匹配
                    (false, 0, None)
                }
            }
            _ => {
                // 如果不是icmp错误信息

                // 使用目的地址, 源地址 生成验证信息, 注意不包含 源端口
                let validation = aes_rand.validate_gen_v6_u128_without_sport(
                    ipv6_header.dest_addr, ipv6_header.source_addr);

                // id 字段是由 验证信息的第10, 11位生成的
                if net_layer_data[4] != validation[10] || net_layer_data[5] != validation[11] {
                    // 如果有一个字节不相等, 直接返回false, 否则进行后续判断
                    return (false, 0, None)
                }

                icmp6_data = &net_layer_data[8..16];
                if icmp6_data.eq(&validation[0..8]) {
                    // 数据部分匹配通过

                    // none 表示不是内层ip
                    (true, 0, None)
                } else {
                    // 数据部分无法匹配
                    (false, 0, None)
                }
            }
        }
    }


    fn print_header(&self) -> Vec<String> {
        //  注意顺序
        let mut output_data = Vec::with_capacity(self.fields_flag.len);
        push_fields_name!(self; output_data; source_addr, outer_source_addr, icmp_type, icmp_code, identifier, sequence, classification);
        
        if self.print_ipv6_packet {
            output_data.extend(Ipv6PacketU128::print_header());
        }
        
        output_data
    }

    fn process_packet_v6(&self, _header: &PacketHeader, _data_link_header: &[u8], ipv6_header: &Ipv6PacketU128, net_layer_data: &[u8], inner_src_ip:Option<u128>) -> (bool, Vec<String>) {

        let mut output_data = Vec::with_capacity(self.fields_flag.len);

        let success_flag;
        if let Some(ip) = inner_src_ip {
            // 如果有 内层ip
            success_flag = false;
            push_fields_val!(self; output_data; (source_addr, Ipv6Addr::from(ip)), (outer_source_addr, Ipv6Addr::from(ipv6_header.source_addr)));
        } else {
            // 如果没有内层ip, 直接使用外层ip
            success_flag = true;
            push_fields_val!(self; output_data; (source_addr, Ipv6Addr::from(ipv6_header.source_addr)), (outer_source_addr, ""));
        }

        if self.fields_flag.icmp_fields_exist {
            // 使用网络层数据生成icmp_v6报头

            if success_flag {
                // 正常响应
                push_fields_val!(self; output_data;
                    (icmp_type, net_layer_data[0]),
                    (icmp_code, net_layer_data[1]),
                    (identifier, ((net_layer_data[4] as u16) << 8) | (net_layer_data[5] as u16)),
                    (sequence, ((net_layer_data[6] as u16) << 8) | (net_layer_data[7] as u16)));
            } else {
                // icmp 错误报文
                push_fields_val!(self; output_data;
                    (icmp_type, net_layer_data[0]),
                    (icmp_code, net_layer_data[1]),
                    (identifier, ""),
                    (sequence, ""));
            }
        }

        if self.fields_flag.classification {
            if net_layer_data[0] == 129 {
                output_data.push(String::from("echo_reply"));
            } else {
                let classification = IcmpV6Fields::parse_icmp6_classification(net_layer_data[0], net_layer_data[1]);
                output_data.push(classification);
            }
        }
        
        if self.print_ipv6_packet {
            output_data.extend(ipv6_header.print());
        }

        (success_flag, output_data)
    }
}