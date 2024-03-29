use std::net::Ipv4Addr;
use chrono::Utc;
use libc::timeval;
use crate::modules::probe_modules::tools::ethernet::make_ethernet_header;
use crate::modules::probe_modules::topology_probe::tools::default_ttl::get_default_ttl;
use crate::modules::probe_modules::topology_probe::tools::others::get_dest_port;
use crate::modules::probe_modules::topology_probe::topo_mod_v4::{TopoMethodV4, TopoResultV4};
use crate::modules::probe_modules::topology_probe::v4::topo_tcp::TopoTcpV4;
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;
use crate::tools::net_handle::packet::tcp::TcpPacket;
use crate::tools::net_handle::packet::v4::packet_v4_u32::Ipv4PacketU32;

impl TopoMethodV4 for TopoTcpV4 {
    fn thread_initialize_v4(&mut self, local_mac: &MacAddress, gateway_mac: &MacAddress) {
        //  填充以太网首部字段 14字节       以太网类型为 ipv4 在以太网类型字段中的标识
        make_ethernet_header(&mut self.base_buf, local_mac, gateway_mac, 0x0800u16);

        //  没有 地址 的ipv4首部字段
        let ipv4_header_without_addrs = Ipv4PacketU32 {
            ihl: 5,                  // 首部长度为 5 * 4 = 20字节
            tos: 0,                  // 服务类型
            total_len: 40,           // 长度: ipv4首部(20字节) + tcp报文(20字节) = 40字节

            // 以下项无效
            id: 0,                   // 16位标识唯一地标识主机发送的每一个数据报。

            rf: 0,
            df: 0,
            mf: 0,
            offset: 0,

            ttl: 64,                 // 初始ttl
            protocol: 6,            // tcp 在 ipv4 中的协议号为 6

            // 无论该项输入是什么, 输出字节数组时都会被置为 0
            header_check_sum: 0,
            // 以下几项无效, 不会出现在得到的字节数组中
            source_addr: 0,
            dest_addr: 0,
        }.get_u8_vec_without_addr();
        //  填充 ipv4 首部前4固定字节
        self.base_buf.extend_from_slice(&ipv4_header_without_addrs[..4]);
        //  填充 ipv4 的 id字段之后 到 地址 之前的 6 字节
        self.ipv4_header_base_buf_2.extend_from_slice(&ipv4_header_without_addrs[6..12]);
        
        //  填充 tcp首部序列号之后的部分, 注意包含check_sum
        self.tcp_header_after_seq.extend(TcpPacket {
            // 以下三项无效, 也不会传入
            sport: 0,
            dport: 0,
            sequence_num: 0,

            ack_num: 0,
            header_len: 5,      // 5*4=20字节基本首部
            urg: 0,
            ack: if self.use_ack { 1 } else { 0 },          // 根据用户指定， 选择使用 syn 或 syn_ack
            psh: 0,
            rst: 0,
            syn: 1,
            fin: 0,
            window_size: 2048,
            check_sum: 0,        // 该项无效, 获取字节数组时将被自动设置为 0
            urgent_pointer: 0, 
        }.get_u8_vec_after_sequence());
    }

    fn make_packet_v4(&self, source_ip: u32, dest_ip: u32, dest_port_offset:Option<u16>, ttl: u8, aes_rand: &AesRand) -> Vec<u8> {
        let mut packet = Vec::with_capacity(54);
        
        // 将 源地址, 目标地址 转换为 大端数组
        let source_ip_bytes = source_ip.to_be_bytes();
        let dest_ip_bytes = dest_ip.to_be_bytes();

        // 生成验证数据
        let validation = aes_rand.validate_gen_v4_u32_without_sport(source_ip, dest_ip);
        {
            // 以太网报头: [ 目的地址: { 0, 1, 2, 3, 4, 5}  源地址: { 6, 7, 8, 9, 10, 11 }  标识 { 12, 13 } ]
            // ipv4 报头: [ 版本号: {14( 1111_0000 ) }, 首部长度: {14( 0000_1111 )}, 服务类型: {15} ]
            //           [ 总长度: {16, 17}, id: {18, 19}, 标志: rf:{20 (1_000_0000), df:20 (0_1_00_0000), mf:20 (00_1_0_0000)}]
            //           [ 片偏移: {20 (000_11111), 21}, ttl: {22}, 协议: {23}, 校验和: {24, 25}]
            //           [ 源地址: {26, 27, 28, 29}, 目的地址: {30, 31, 32, 33} ]

            // 写入 以太网首部, ipv4首部前4字节
            packet.extend_from_slice(&self.base_buf);

            // 写入 id字段(原始ttl)
            packet.extend([ttl, validation[11]]);
            
            // 写入 ipv4 的 id字段之后 到 地址 之前的 6 字节
            packet.extend_from_slice(&self.ipv4_header_base_buf_2);
            
            // 写入 ttl字段
            packet[22] = ttl;

            // 写入 ipv4源地址
            packet.extend(source_ip_bytes);

            // 写入 ipv4目的地址
            packet.extend(dest_ip_bytes);

            // 写入 ipv4首部校验和
            let checksum = Ipv4PacketU32::get_check_sum_from_buf(&packet[14..34]);
            packet[24] = checksum[0]; packet[25] = checksum[1];
        }
        
        {
            // tcp 报头(20字节): [ 源端口: {34, 35}   目的端口: {36, 37} ]
            //                  [ 序列号: {38, 39, 40, 41} ]
            //                  [ 确认号: {42, 43, 44, 45} ]
            //                  [ 数据偏移: {46(1111_0000)}  保留字段:{46(0000_1111), 47(11_000000)} 标记字段:{47(00_111111)} 窗口:{48, 49} ]
            //                  [ 校验和: {50, 51} 紧急指针{52, 53} ]

            // 写入 源端口 (2字节)   注意: 只要validation确定(源地址, 目的地址, 目标端口的组合确定), 得到的源端口就是确定的
            {   // 下标为 0..len-1(最大为65535),  以验证字段前两个字节作为随机索引, 从源端口向量中提取源端口
                let sport_index = ((validation[0] as usize) << 8) | (validation[1] as usize);
                let sport = self.tcp_sports[ sport_index % self.tcp_sports_len ];
                packet.extend(sport.to_be_bytes());
            }

            // 写入 目标端口 (2字节)
            // 如果不存在偏移值, 使用默认的目标端口
            // 如果存在偏移值, 根据偏移值生成新的目标端口
            let dest_port = dest_port_offset.map_or(self.default_dest_port,
                                                    |offset|{ get_dest_port(self.default_dest_port, offset) }).to_be_bytes();
            packet.extend(dest_port);

            // 写入 序列号 (4字节)
            if self.use_time_encoding { // 如果启用时间戳编码 序列号部分为 时间戳编码
                packet.extend((Utc::now().timestamp_millis() as u32).to_be_bytes());
            } else { // 如果不启用时间戳编码  序列号部分为 验证字段前四个字节
                packet.extend(&validation[0..4]);
            }

            // 写入 tcp首部 序列号以后的部分 (12字节)
            packet.extend_from_slice(&self.tcp_header_after_seq);

            let tcp_check_sum_bytes = TcpPacket::get_check_sum_v4(&source_ip_bytes, &dest_ip_bytes, 20, &packet[34..54]);
            packet[50] = tcp_check_sum_bytes[0]; packet[51] = tcp_check_sum_bytes[1];
        }
        packet
    }

    fn parse_packet_v4(&self, ts: &timeval, ipv4_header: &[u8], net_layer_data: &[u8], aes_rand: &AesRand) -> Option<TopoResultV4> {
        // ip报头协议字段必须为 icmp
        // 如果存在内层数据包, 网络层应至少包含  外层icmp(8字节) + 内层ipv4报头(20字节) + 内层tcp报头前8字节 = 36
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
        let inner_tcp_header_data = &inner_ipv4[20..];

        // 取出内部数据包中的地址信息
        let inner_src_ip = Ipv4PacketU32::get_source_addr(inner_ipv4);
        let inner_dest_ip = Ipv4PacketU32::get_dest_addr(inner_ipv4);

        // 使用 内层udp源端口 进行校验
        {
            // 生成验证信息
            let validation = aes_rand.validate_gen_v4_u32_without_sport(inner_src_ip, inner_dest_ip);

            let sport = ((inner_tcp_header_data[0] as u16) << 8) | (inner_tcp_header_data[1] as u16);

            let local_sport;
            {   // 使用 验证信息还原 发送时使用的源端口, 目标端口参与验证信息计算, 因此不需要单独检验
                let local_sport_index = ((validation[0] as usize) << 8) | (validation[1] as usize);
                local_sport = self.tcp_sports[local_sport_index % self.tcp_sports_len];
            }

            // 检查 源端口
            if local_sport != sport { return  None }
        }

        // 提取 数据包 的 源ip
        let src_ip = Ipv4PacketU32::get_source_addr(ipv4_header);

        // 提取 发送时 的 ttl   注意原始ttl编码在id的第1字节
        let original_ttl = inner_ipv4[4];

        // 计算距离
        let distance = if from_destination { original_ttl - inner_ipv4[8] + 1 } else { original_ttl };
        
        // 计算 经过的时间
        let spent_time = if self.use_time_encoding {

            // 提取 发送时的 时间戳(注意为 u32类型)
            let ori_time_bytes = &inner_tcp_header_data[4..8];
            let original_time = u32::from_be_bytes(ori_time_bytes.try_into().unwrap());

            // 接收时的时间戳(只取 最后32比特)   以毫秒为粒度 (此处务必仔细检查)
            let now_time = ((ts.tv_sec as u64) * 1000) + ((ts.tv_usec as u64) / 1000);
            // 提取 毫秒时间戳 的最后32比特
            let now_time = (now_time & 0xffff_ffff) as u32;

            // 计算 经过时间
            now_time - original_time
        } else { 0 };   // 如果未选择编码时间戳, 往返时延将被置为0

        Some(
            TopoResultV4 {
                dest_ip: inner_dest_ip,
                responder: src_ip,
                distance,
                from_destination,
                rtt: spent_time as u16,
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

    fn print_record(&self, res: &TopoResultV4, ipv4_header: &[u8]) -> Vec<String> {
        let mut output_data = Vec::with_capacity(self.output_len);
        output_data.extend(vec![Ipv4Addr::from(res.dest_ip).to_string(), Ipv4Addr::from(res.responder).to_string(), res.distance.to_string()]);

        if self.use_time_encoding { output_data.push(res.rtt.to_string()); }
        if self.print_default_ttl {
            let responder_default_ttl = get_default_ttl(res.distance, ipv4_header[8]);
            output_data.push(responder_default_ttl.to_string());
        }
        output_data
    }

    fn print_silent_record(&self, dest_ip: u32, distance: u8) -> Vec<String> {
        let mut output_data = Vec::with_capacity(self.output_len);
        output_data.extend(vec![Ipv4Addr::from(dest_ip).to_string(), "null".to_string(), distance.to_string()]);

        if self.use_time_encoding { output_data.push("null".to_string()); }
        if self.print_default_ttl { output_data.push("null".to_string()); }
        output_data
    }
}