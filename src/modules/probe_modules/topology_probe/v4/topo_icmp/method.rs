use std::net::Ipv4Addr;
use chrono::Utc;
use libc::timeval;
use crate::modules::probe_modules::tools::ethernet::make_ethernet_header;
use crate::modules::probe_modules::topology_probe::tools::default_ttl::{get_default_ttl, infer_default_ttl_by_outer_ttl};
use crate::modules::probe_modules::topology_probe::topo_mod_v4::{TopoMethodV4, TopoResultV4};
use crate::modules::probe_modules::topology_probe::v4::topo_icmp::TopoIcmpV4;
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;
use crate::tools::net_handle::packet::v4::icmp_v4::IcmpV4Packet;
use crate::tools::net_handle::packet::v4::packet_v4_u32::Ipv4PacketU32;

impl TopoMethodV4 for TopoIcmpV4 {
    fn thread_initialize_v4(&mut self, local_mac: &MacAddress, gateway_mac: &MacAddress) {
        //  填充以太网首部字段 14字节       以太网类型为 ipv4 在以太网类型字段中的标识
        make_ethernet_header(&mut self.base_buf, local_mac, gateway_mac, 0x0800u16);

        //  没有 地址 的ipv4首部字段
        let ipv4_header_without_addrs = Ipv4PacketU32 {
            ihl: 5,                  // 首部长度为 5 * 4 = 20字节
            tos: 0,                  // 服务类型
            total_len: 28,           // 长度为 ipv4首部(20字节) + icmp固定首部(8字节)

            // 注意: id字段被用于 设置 ttl(第一字节), 验证数据生成的随机值(第二字节), 此处设置无效
            id: 0,                   // 16位标识唯一地标识主机发送的每一个数据报。

            rf: 0,
            df: 0,
            mf: 0,
            offset: 0,

            ttl: 64,                 // 初始ttl
            protocol: 1,            // icmp_v4 在 ipv4 中的协议号为 1

            // 无论该项输入是什么, 输出字节数组时都会被置为 0
            header_check_sum: 0,
            // 以下几项无效, 不会出现在得到的字节数组中
            source_addr: 0,
            dest_addr: 0,
        }.get_u8_vec_without_addr();

        //  填充 ipv4首部 id字段 之前的 4字节
        self.base_buf.extend_from_slice(&ipv4_header_without_addrs[..4]);

        // 填充 ipv4 的 id字段之后 到 地址 之前的 6 字节
        self.ipv4_header_base_buf_2.extend_from_slice(&ipv4_header_without_addrs[6..12]);
    }

    fn make_packet_v4(&self, source_ip: u32, dest_ip: u32, _dest_port_offset:Option<u16>, ttl: u8, aes_rand: &AesRand) -> Vec<u8> {

        // 按最大数据包长度(42字节)设置 向量容量
        let mut packet = Vec::with_capacity(42);

        // 生成验证信息, 注意这里是 源地址在前
        let validation = aes_rand.validate_gen_v4_u32_without_sport(source_ip, dest_ip);

        // 以太网 和 ipv4首部填充
        {
            // 以太网报头: [ 目的地址: { 0, 1, 2, 3, 4, 5}  源地址: { 6, 7, 8, 9, 10, 11 }  标识 { 12, 13 } ]
            // ipv4 报头: [ 版本号: {14( 1111_0000 ) }, 首部长度: {14( 0000_1111 )}, 服务类型: {15} ]
            //           [ 总长度: {16, 17}, id: {18, 19}, 标志: rf:{20 (1_000_0000), df:20 (0_1_00_0000), mf:20 (00_1_0_0000)}]
            //           [ 片偏移: {20 (000_11111), 21}, ttl: {22}, 协议: {23}, 校验和: {24, 25}]
            //           [ 源地址: {26, 27, 28, 29}, 目的地址: {30, 31, 32, 33} ]

            // 写入 以太网首部, id字段之前 的 ipv4首部
            packet.extend_from_slice(&self.base_buf);

            // 写入 id字段( ttl作为第一字节, 验证数据的第11字节作为第二字节 )
            packet.extend([ttl, validation[11]]);

            // 写入 id字段 之后到 地址 之前的数据
            packet.extend_from_slice(&self.ipv4_header_base_buf_2);

            // 写入 ttl
            packet[22] = ttl;

            // 写入 ipv4源地址
            packet.extend(source_ip.to_be_bytes());

            // 写入 ipv4目的地址
            packet.extend(dest_ip.to_be_bytes());

            // 写入 ipv4首部校验和
            let checksum = Ipv4PacketU32::get_check_sum_from_buf(&packet[14..34]);
            packet[24] = checksum[0];
            packet[25] = checksum[1];
        }

        // 填充icmp报文
        {
            // icmp报头: [ 类型: {34}  代码: {35}  校验和: {36, 37} id: {38, 39} 序列号: {40, 41} ]

            // 时间戳编码
            let send_time= ((Utc::now().timestamp_millis() & 0xffff) as u16).to_be_bytes();

            // 写入 icmp_v4首部
            packet.extend([
                //   类型为回显请求      code                           校验和置为0
                8,                 0,                           0,                     0,
                //   id                                        序列号
                send_time[1],    validation[9],     validation[7],           send_time[0]
            ]);

            let icmp4_check_sum_bytes = IcmpV4Packet::get_check_sum(&packet[34..42]);
            packet[36] = icmp4_check_sum_bytes[0];
            packet[37] = icmp4_check_sum_bytes[1];
        }
        packet
    }

    fn parse_packet_v4(&self, ts: &timeval, ipv4_header: &[u8], net_layer_data: &[u8], aes_rand: &AesRand) -> Option<TopoResultV4> {
        // ip报头协议字段必须为 icmp
        if ipv4_header[9] != 1 || net_layer_data.len() < 8 { return None }

        // 如果icmp类型为  ICMP_ECHO_REPLY
        // 注意: 该类型为从 目标地址 返回的 正常icmp响应 
        if net_layer_data[0] == 0 {
            let src_ip = Ipv4PacketU32::get_source_addr(ipv4_header);
            let dest_ip = Ipv4PacketU32::get_dest_addr(ipv4_header);
            let validation = aes_rand.validate_gen_v4_u32_without_sport(dest_ip, src_ip);

            // 判断 验证数据
            if net_layer_data[5] != validation[9] || net_layer_data[6] != validation[7] { return None }

            let outer_ttl = ipv4_header[8];

            // 如果进行了 时间编码, 提取 发送时的时间戳
            let rtt = if self.use_time_encoding {
                // 提取 发送时的 时间戳
                let original_time = ((net_layer_data[7] as u16) << 8) | (net_layer_data[4] as u16);
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
            } else { 0 };

            return Some(TopoResultV4 {
                dest_ip: src_ip,
                responder: src_ip,
                distance: infer_default_ttl_by_outer_ttl(outer_ttl) - outer_ttl + 1,
                from_destination: true,
                rtt,
            })
        }
        // 如果存在内层数据包, 网络层应至少包含  外层icmp(8字节) + 内层ipv4报头(20字节) + 内层icmp首部(8字节) = 36
        if net_layer_data.len() < 36 { return None }
        
        // 是否是来自 目的地址 或 目标网络(主机不可达消息) 的响应
        let from_destination= match net_layer_data[0] {
            // 如果 ICMP类型字段 为 目标不可达
            3 => {
                match net_layer_data[1] {
                    // 主机不可达
                    1 => if self.allow_tar_network_respond { true } else { return None },
                    _ => return None,
                }
            }
            // 生存时间为0
            11 => false,
            _ => return None
        };

        let inner_ipv4 = &net_layer_data[8..];
        let inner_icmp = &inner_ipv4[20..];

        // 取出内部数据包中的地址信息
        let inner_src_ip = Ipv4PacketU32::get_source_addr(inner_ipv4);
        let inner_dest_ip = Ipv4PacketU32::get_dest_addr(inner_ipv4);

        // 生成验证信息
        let validation = aes_rand.validate_gen_v4_u32_without_sport(inner_src_ip, inner_dest_ip);

        // 判断 验证数据 (内层icmp)
        if inner_icmp[5] != validation[9] || inner_icmp[6] != validation[7] { return None }

        // 提取 外层数据包 的 源ip
        let src_ip = Ipv4PacketU32::get_source_addr(ipv4_header);

        // 提取 发送时 的 ttl
        let original_ttl = inner_ipv4[4];

        // 计算距离
        let distance = if from_destination { original_ttl - inner_ipv4[8] + 1 } else { original_ttl };

        // 如果进行了 时间编码, 提取 发送时的时间戳
        let rtt = if self.use_time_encoding {
            // 提取 发送时的 时间戳
            let original_time = ((inner_icmp[7] as u16) << 8) | (inner_icmp[4] as u16);
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
        } else { 0 };
        
        Some(
            TopoResultV4 {
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

    fn print_record(&self, res: &TopoResultV4, ipv4_header:&[u8]) -> Vec<String> {
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