use std::net::Ipv4Addr;
use chrono::Utc;
use crate::modules::probe_modules::tools::ethernet::make_ethernet_header;
use crate::modules::probe_modules::topology_probe::tools::default_ttl::get_default_ttl;
use crate::modules::probe_modules::topology_probe::topo_mod_v4::{TopoMethodV4, TopoResultV4};
use crate::modules::probe_modules::topology_probe::v4::topo_udp::TopoUdpV4;
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;
use crate::tools::net_handle::packet::udp::UdpPacket;
use crate::tools::net_handle::packet::v4::packet_v4_u32::Ipv4PacketU32;

impl TopoMethodV4 for TopoUdpV4 {
    fn thread_initialize_v4(&mut self, local_mac: &MacAddress, gateway_mac: &MacAddress) {
        //  填充以太网首部字段 14字节       以太网类型为 ipv4 在以太网类型字段中的标识
        make_ethernet_header(&mut self.base_buf, local_mac, gateway_mac, 0x0800u16);

        //  没有 地址 的ipv4首部字段
        let ipv4_header_without_addrs = Ipv4PacketU32 {
            ihl: 5,                  // 首部长度为 5 * 4 = 20字节
            tos: 0,                  // 服务类型

            // 以下两项无效
            total_len: 20,           // 总长度
            id: 0,                   // 16位标识唯一地标识主机发送的每一个数据报。

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
        }.get_u8_vec_without_addr();

        //  填充 ipv4 首部前两固定字节
        self.base_buf.extend_from_slice(&ipv4_header_without_addrs[..2]);

        // 填充 ipv4 的 id字段之后 到 地址 之前的 6 字节
        self.ipv4_header_base_buf_2.extend_from_slice(&ipv4_header_without_addrs[6..12]);
    }

    fn make_packet_v4(&self, source_ip: u32, dest_ip: u32, ttl: u8, aes_rand: &AesRand) -> Vec<u8> {
        // 使用当前时间戳 计算 ipv4首部中的 总长度 和 id 字段
        let mut ip_id;
        let mut expected_packet_size:u16 = 64;          // 保证 ipv4数据包总长度至少为 64字节
        {
            //  ip_id  =  [  0..(10比特)  ｜  ttl(6比特)  ]
            ip_id = (ttl & 0x3F) as u16;

            if self.use_time_encoding {

                // 当前时间戳(只取 最后16比特)   以毫秒为粒度
                let now_time = (Utc::now().timestamp_millis() & 0xffff) as u16;

                //  ip_id = [ 当前时间戳 后10比特 |  ttl(6比特)  ]
                ip_id |= now_time << 6;

                //  expected_packet_size = [ 0..(9比特) ｜ 1 ｜ 当前时间戳 前6比特 ]
                expected_packet_size |= now_time >> 10;
            }
        }

        // 包括 以太网首部 在内的数据包总长度
        let total_len = 14 + (expected_packet_size as usize);

        // 设置 向量容量
        let mut packet = Vec::with_capacity(total_len);

        let source_ip_bytes = source_ip.to_be_bytes();
        let dest_ip_bytes = dest_ip.to_be_bytes();
        {
            // 以太网报头: [ 目的地址: { 0, 1, 2, 3, 4, 5}  源地址: { 6, 7, 8, 9, 10, 11 }  标识 { 12, 13 } ]
            // ipv4 报头: [ 版本号: {14( 1111_0000 ) }, 首部长度: {14( 0000_1111 )}, 服务类型: {15} ]
            //           [ 总长度: {16, 17}, id: {18, 19}, 标志: rf:{20 (1_000_0000), df:20 (0_1_00_0000), mf:20 (00_1_0_0000)}]
            //           [ 片偏移: {20 (000_11111), 21}, ttl: {22}, 协议: {23}, 校验和: {24, 25}]
            //           [ 源地址: {26, 27, 28, 29}, 目的地址: {30, 31, 32, 33} ]

            // 写入 以太网首部, ipv4首部的前两固定字节
            packet.extend_from_slice(&self.base_buf);

            // 写入 总长度
            packet.extend(expected_packet_size.to_be_bytes());

            // 写入 id
            packet.extend(ip_id.to_be_bytes());

            // 写入 id字段之后 到 地址 之前的 6 字节
            packet.extend_from_slice(&self.ipv4_header_base_buf_2);

            // 写入 ttl 字段
            packet[22] = ttl;

            // 写入 ipv4源地址
            packet.extend(source_ip_bytes);

            // 写入 ipv4目的地址
            packet.extend(dest_ip_bytes);

            // 写入 ipv4首部校验和
            let checksum = Ipv4PacketU32::get_check_sum_from_buf(&packet[14..34]);
            packet[24] = checksum[0];
            packet[25] = checksum[1];
        }

        let validation = aes_rand.validate_gen_v4_u32_without_sport(source_ip, dest_ip);
        {
            // udp 报头: [源端口: {34, 35}  目的端口: {36, 37}]
            //          [ udp长度: {38, 39}   udp校验和: {40, 41}, udp载荷:{42..(总长度 - 1)}]

            // 写入 源端口 (2字节)
            {   // 下标为 0..len-1(最大为65535),  以验证字段前两个字节作为随机索引, 从源端口向量中提取源端口
                let sport_index = ((validation[0] as usize) << 8) | (validation[1] as usize);
                let sport = self.udp_sports[ sport_index % self.udp_sports_len ];
                packet.extend(sport.to_be_bytes());
            }

            // 写入 目标端口 (2字节)
            packet.extend(self.udp_dest_port.to_be_bytes());

            // 写入 udp长度  20 为 ipv4首部长度
            let udp_len = expected_packet_size - 20;
            packet.extend(udp_len.to_be_bytes());

            // 写入 填充为0的 check_sum字段
            packet.extend([0u8,0]);

            // 写入 udp数据部分   长度为 udp长度 - udp首部长度
            packet.extend_from_slice(&self.udp_payload[..(udp_len as usize - 8)]);

            // 计算并写入 udp校验和
            let udp_check_sum_bytes = UdpPacket::get_check_sum_v4(
                &source_ip_bytes, &dest_ip_bytes, udp_len as u32, &packet[34..total_len]);
            packet[40] = udp_check_sum_bytes[0];
            packet[41] = udp_check_sum_bytes[1];
        }

        packet
    }

    fn parse_packet_v4(&self, ts:&libc::timeval, ipv4_header:&[u8], net_layer_data:&[u8], aes_rand:&AesRand) -> Option<TopoResultV4> {

        // ip报头协议字段必须为 icmp
        // 如果存在内层数据包, 网络层应至少包含  外层icmp(8字节) + 内层ipv4报头(20字节) + 内层udp报头(8字节) = 36
        if ipv4_header[9] != 1 || net_layer_data.len() < 36 { return None }

        // 是否是来自 目的地址 或 目标网络(主机不可达消息) 的响应
        let from_destination= match net_layer_data[0] {
            // 如果 ICMP类型字段 为 目标不可达
            3 => {
                match net_layer_data[1] {
                    // 协议不可达, 端口不可达
                    2 | 3 => true,
                    // 主机不可达
                    1 => if self.allow_tar_network_respond { true } else { return None },
                    _ => return None,
                }
            }
            // 生存时间为0
            11 => false,
            _ => return None,
        };
        
        let inner_ipv4 = &net_layer_data[8..];

        // 取出内部数据包中的地址信息
        let inner_src_ip = Ipv4PacketU32::get_source_addr(inner_ipv4);
        let inner_dest_ip = Ipv4PacketU32::get_dest_addr(inner_ipv4);

        // 使用 内层udp源端口 进行校验
        {
            let inner_udp_header_data = &inner_ipv4[20..];

            // 生成验证信息
            let validation = aes_rand.validate_gen_v4_u32_without_sport(inner_src_ip, inner_dest_ip);

            let sport = ((inner_udp_header_data[0] as u16) << 8) | (inner_udp_header_data[1] as u16);

            let local_sport;
            {   // 使用 验证信息还原 发送时使用的源端口, 目标端口参与验证信息计算, 因此不需要单独检验
                let local_sport_index = ((validation[0] as usize) << 8) | (validation[1] as usize);
                local_sport = self.udp_sports[local_sport_index % self.udp_sports_len];
            }

            // 检查 源端口
            if local_sport != sport { return  None }
        }

        // 提取 数据包 的 源ip
        let src_ip = Ipv4PacketU32::get_source_addr(ipv4_header);

        // 提取 发送时 的 ttl
        let original_ttl = inner_ipv4[5] & 0x3f;

        // 计算距离
        let distance = if from_destination { original_ttl - inner_ipv4[8] + 1 } else { original_ttl };

        // 计算 经过的时间
        let spent_time = if self.use_time_encoding {
            // 提取 内层ip数据包 的 id字段
            // [ 当前时间戳 后10比特 |  ttl(6比特)  ]
            let inner_ip_id= ((inner_ipv4[4] as u16) << 8) | (inner_ipv4[5] as u16);
            // [ 0..(9比特) ｜ 1 ｜ 当前时间戳 前6比特 ]
            let inner_ip_total_len = ((inner_ipv4[2] as u16) << 8) | (inner_ipv4[3] as u16);

            // 提取 发送时的 时间戳
            let original_time = (inner_ip_total_len << 10) | (inner_ip_id >> 6);

            // 接收时的时间戳(只取 最后16比特)   以毫秒为粒度 (此处务必仔细检查)
            let now_time = ((ts.tv_sec as u64) * 1000) + ((ts.tv_usec as u64) / 1000);
            // 提取 毫秒时间戳 的最后16比特
            let now_time = (now_time & 0xffff) as u16;

            // 警告: 由于只编码了16位的时间戳，当 实际往返时间 超过 65秒时, 得到的时延信息将出错
            if now_time >= original_time {
                // 如果 接收时的时间 大于等于 发送时 的 时间
                now_time - original_time
            } else {
                // 如果 发送时的时间 小于 发送时 的 时间
                now_time + (u16::MAX - original_time)
            }
        } else { 0 };   // 如果未选择编码时间戳, 往返时延将被置为0

        Some(
            TopoResultV4 {
                dest_ip: inner_dest_ip,
                responder: src_ip,
                distance,
                from_destination,
                rtt: spent_time,
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

    fn print_record(&self, res:&TopoResultV4, ipv4_header:&[u8]) -> Vec<String> {
        let mut output_data = Vec::with_capacity(self.output_len);
        output_data.extend(vec![Ipv4Addr::from(res.dest_ip).to_string(), Ipv4Addr::from(res.responder).to_string(), res.distance.to_string()]);
        
        if self.use_time_encoding { output_data.push(res.rtt.to_string()); }
        if self.print_default_ttl {
            let responder_default_ttl = get_default_ttl(res.distance, ipv4_header[8]);
            output_data.push(responder_default_ttl.to_string()); 
        }
        output_data
    }

    fn print_silent_record(&self, dest_ip: u32, distance:u8) -> Vec<String> {
        let mut output_data = Vec::with_capacity(self.output_len);
        output_data.extend(vec![Ipv4Addr::from(dest_ip).to_string(), "null".to_string(), distance.to_string()]);

        if self.use_time_encoding { output_data.push("null".to_string()); }
        if self.print_default_ttl { output_data.push("null".to_string()); }
        output_data
    }
}


