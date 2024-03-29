use std::net::Ipv6Addr;
use chrono::Utc;
use libc::timeval;
use crate::modules::probe_modules::tools::ethernet::make_ethernet_header;
use crate::modules::probe_modules::topology_probe::tools::default_ttl::{get_default_ttl, infer_default_ttl_by_outer_ttl};
use crate::modules::probe_modules::topology_probe::topo_mod_v6::{TopoMethodV6, TopoResultV6};
use crate::modules::probe_modules::topology_probe::v6::topo_icmp::TopoIcmpV6;
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;
use crate::tools::net_handle::packet::v6::icmp_v6::IcmpV6Packet;
use crate::tools::net_handle::packet::v6::packet_v6_u128::Ipv6PacketU128;

impl TopoMethodV6 for TopoIcmpV6 {
    fn thread_initialize_v6(&mut self, local_mac: &MacAddress, gateway_mac: &MacAddress) {
        //  填充以太网首部字段 14字节       以太网类型为 ipv6 在以太网类型字段中的标识
        make_ethernet_header(&mut self.base_buf, local_mac, gateway_mac,0x86DDu16);

        // 填充不连地址的ipv6首部字段  8字节
        self.base_buf.extend(Ipv6PacketU128 {
            traffic_class: 0,
            flow_label: 0,

            payload_len: 16,             // 负载长度  icmp_v6首部(8字节) + 8字节数据
            next_header: 58,             // 下一首部指向icmp_v6协议
            hop_limit: 64,              // 设置初始ttl

            // 这两项无效, 同时也不会传入
            source_addr: 0,
            dest_addr: 0,
        }.get_u8_vec_without_addr());
    }

    fn make_packet_v6(&self, source_ip: u128, dest_ip: u128, _dest_port_offset:Option<u16>, hop_limit: u8, aes_rand: &AesRand) -> Vec<u8> {
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

            // 写入 跳数限制
            packet[21] = hop_limit;

            // 写入 ipv6源地址
            packet.extend(source_ip_bytes);

            // 写入 ipv6目的地址
            packet.extend(dest_ip_bytes);
        }

        {
            // icmp报头: [ 类型: {54}  代码: {55}  校验和: {56, 57} id: {58(验证数据10), 59(验证数据11)} 序列号: {60(hop_limit), 61(send_time)} ]
            // icmp数据: [ 62 .. <总长度]

            // icmp数据: [ 62, 63, 64, 65,  66, 67, 68,(时间戳) | 69(验证数据12) ]
            
            // 时间戳编码  注意为 小端字节
            let send_time_le_bytes= Utc::now().timestamp_millis().to_le_bytes();

            // 生成验证信息, 注意这里是 源地址在前
            let validation = aes_rand.validate_gen_v6_u128_without_sport(source_ip, dest_ip);

            // 写入icmp_v6首部
            packet.extend([
                //        类型              code                      check_sum字段填充为0
                           128,               0,                  0,                  0,
                // 使用验证数据的 第10, 11位(大端字节)作为id       序列号第一字节
                validation[10],  validation[11],          hop_limit,
            ]);

            // 写入时间戳  序列号第2字节 至 数据第7字节
            packet.extend(send_time_le_bytes);
            
            // 将 验证数据第12字节写入 数据第8字节
            packet.push(validation[12]);

            let check_sum_bytes = IcmpV6Packet::get_check_sum(&source_ip_bytes, &dest_ip_bytes,
                                                              // len: 8字节(icmp首部) + 8字节(数据)
                                                              16, &packet[54..70]);
            packet[56] = check_sum_bytes[0];
            packet[57] = check_sum_bytes[1];
        }
        packet
    }

    fn parse_packet_v6(&self, ts: &timeval, ipv6_header: &[u8], net_layer_data: &[u8], aes_rand: &AesRand) -> Option<TopoResultV6> {
        // ip报头协议字段必须为 icmp
        // 网络层应至少包含 icmp首部(8字节) + 数据部分(8字节)
        if ipv6_header[6] != 58 || net_layer_data.len() < 16 { return None }

        // 如果icmp类型为  ICMP_ECHO_REPLY
        // 注意: 该类型为从 目标地址 返回的 正常icmp响应
        if net_layer_data[0] == 129 {
            let src_ip = Ipv6PacketU128::get_source_addr(ipv6_header);
            let dest_ip = Ipv6PacketU128::get_dest_addr(ipv6_header);
            let validation = aes_rand.validate_gen_v6_u128_without_sport(dest_ip, src_ip);

            // 判断 验证数据
            if net_layer_data[4] != validation[10] || net_layer_data[5] != validation[11] { return None }

            let outer_ttl = ipv6_header[7];

            // 如果进行了 时间编码, 提取 发送时的时间戳
            let rtt = if self.use_time_encoding {

                // 提取 发送时的 时间戳
                let ori_time_le_bytes = &net_layer_data[7..15];
                let original_time = u64::from_le_bytes(ori_time_le_bytes.try_into().unwrap());

                // 接收时的时间戳
                let now_time = ((ts.tv_sec as u64) * 1000) + ((ts.tv_usec as u64) / 1000);

                // 计算 经过时间
                now_time - original_time
            } else { 0 };

            return Some(TopoResultV6 {
                dest_ip: src_ip,
                responder: src_ip,
                distance: infer_default_ttl_by_outer_ttl(outer_ttl) - outer_ttl + 1,
                from_destination: true,
                rtt,
            })
        }
        // 如果存在内层数据包, 网络层应至少包含  外层icmp(8字节) + 内层ipv6报头(40字节) + 内层icmp报头(8字节) + 数据(8字节) = 64
        if net_layer_data.len() < 64 { return None }

        // 是否是来自 目的地址 或 目标网络(主机不可达消息) 的响应
        let from_destination= match net_layer_data[0] {
            // 如果 ICMP类型字段 为 目标不可达
            1 => {
                match net_layer_data[1] {
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
        let inner_icmp_v6 = &inner_ipv6[40..];

        // 取出内部数据包中的地址信息
        let inner_src_ip  = Ipv6PacketU128::get_source_addr(inner_ipv6);
        let inner_dest_ip = Ipv6PacketU128::get_dest_addr(inner_ipv6);

        // 生成验证信息
        let validation = aes_rand.validate_gen_v6_u128_without_sport(inner_src_ip, inner_dest_ip);

        // 判断 验证数据
        if inner_icmp_v6[4] != validation[10] || inner_icmp_v6[5] != validation[11] { return None }
        
        // 提取 外层数据包 的 源ip
        let src_ip = Ipv6PacketU128::get_source_addr(ipv6_header);
        
        // 提取 发送时 的 hop_limit
        let original_hop_limit = inner_icmp_v6[6];

        // 计算距离
        let distance = if from_destination { original_hop_limit - inner_ipv6[7] + 1 } else { original_hop_limit };

        // 如果进行了 时间编码, 提取 发送时的时间戳
        let rtt = if self.use_time_encoding {
            // 提取 发送时的 时间戳
            let ori_time_le_bytes = &inner_icmp_v6[7..15];
            let original_time = u64::from_le_bytes(ori_time_le_bytes.try_into().unwrap());

            // 接收时的时间戳
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
                rtt,
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