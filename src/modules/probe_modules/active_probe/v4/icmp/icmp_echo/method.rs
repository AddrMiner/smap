use std::net::Ipv4Addr;
use pcap::PacketHeader;
use crate::modules::probe_modules::probe_mod_v4::ProbeMethodV4;
use crate::modules::probe_modules::tools::ethernet::make_ethernet_header;
use crate::modules::probe_modules::v4::IcmpEchoV4;
use crate::{push_fields_name, push_fields_val};
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;
use crate::tools::net_handle::packet::v4::icmp_v4::fields::IcmpV4Fields;
use crate::tools::net_handle::packet::v4::icmp_v4::IcmpV4Packet;
use crate::tools::net_handle::packet::v4::packet_v4_u32::Ipv4PacketU32;


impl ProbeMethodV4 for IcmpEchoV4 {

    /// 在发送线程开始时准备以太网首部, ipv4 检验和, 地址前的首部
    fn thread_initialize_v4(&mut self, local_mac: &MacAddress, gateway_mac: &MacAddress, rand_u16:u16) {

        //  填充以太网首部字段 14字节       以太网类型为 ipv4 在以太网类型字段中的标识
        make_ethernet_header(&mut self.base_buf, local_mac, gateway_mac, 0x0800u16);

        //  填充没有 地址 的ipv4首部字段  12字节
        self.base_buf.extend(Ipv4PacketU32 {
            ihl: 5,                  // 首部长度为 5 * 4 = 20字节
            tos: 0,                  // 服务类型
            total_len: 28 + (self.payload.len() as u16),           // 长度为 ipv4首部(20字节) + icmp固定首部(8字节) + icmp数据部分 = 28 字节 + 数据部分

            // 16位标识唯一地标识主机发送的每一个数据报。每发送一个数据报，其值就加1。该值在数据报分片时被复制到每个分片中，因此同一个数据报的所有分片都具有相同的标识值。
            // 警告: 该固定字段可用于识别 扫描流量, 隐秘化扫描应使用随机值
            id: rand_u16,

            rf: 0,
            df: 0,
            mf: 0,
            offset: 0,

            ttl: 64,                // 初始ttl
            protocol: 1,            // icmp_v4 在 ipv4 中的协议号为 1

            // 无论该项输入是什么, 输出字节数组时都会被置为 0
            header_check_sum: 0,
            // 以下几项无效, 不会出现在得到的字节数组中
            source_addr: 0,
            dest_addr: 0,
        }.get_u8_vec_without_addr());
    }

    fn make_packet_v4(&self, source_ip: u32, dest_ip: u32, _dest_port: u16, ttl:Option<u8>, aes_rand: &AesRand) -> Vec<u8> {
        // 按最大数据包长度设置 向量容量
        let mut packet = Vec::with_capacity(self.max_len);

        // 以太网 和 ipv4首部填充
        {
            // 以太网报头: [ 目的地址: { 0, 1, 2, 3, 4, 5}  源地址: { 6, 7, 8, 9, 10, 11 }  标识 { 12, 13 } ]
            // ipv4 报头: [ 版本号: {14( 1111_0000 ) }, 首部长度: {14( 0000_1111 )}, 服务类型: {15} ]
            //           [ 总长度: {16, 17}, id: {18, 19}, 标志: rf:{20 (1_000_0000), df:20 (0_1_00_0000), mf:20 (00_1_0_0000)}]
            //           [ 片偏移: {20 (000_11111), 21}, ttl: {22}, 协议: {23}, 校验和: {24, 25}]
            //           [ 源地址: {26, 27, 28, 29}, 目的地址: {30, 31, 32, 33} ]

            // 写入 以太网首部, 不含 地址 的 ipv4首部
            packet.extend_from_slice(&self.base_buf);

            // 如果任务需要, 请在此处直接修改上述对应字段(不可晚于计算 校验和 之前)
            if let Some(t) = ttl { packet[22] = t; }

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
            // icmp数据: [ 42 .. <总长度]

            // 生成验证信息, 注意这里是 源地址在前
            let validation = aes_rand.validate_gen_v4_u32_without_sport(source_ip, dest_ip);

            // 写入 icmp_v4首部
            packet.extend([
                //   类型为回显请求      code                           校验和置为0
                            8,                 0,                          0,                         0,
                // 使用验证数据的 第6, 7位(大端字节)作为id         使用验证数据的 第10, 11位(大端字节)作为 序列号
                validation[6],     validation[7],             validation[10],             validation[11]
            ]);

            // 写入icmp载荷
            packet.extend_from_slice(&self.payload);

            let icmp4_check_sum_bytes = IcmpV4Packet::get_check_sum(&packet[34..self.max_len]);
            packet[36] = icmp4_check_sum_bytes[0];
            packet[37] = icmp4_check_sum_bytes[1];
        }
        packet
    }

    fn is_successful(&self, _data_link_header:&[u8], ipv4_header:&Ipv4PacketU32, net_layer_data:&[u8], aes_rand:&AesRand) -> bool {

        // 如果 ipv4首部 中的 协议号 对应的不是 icmp_v4
        // 网络层数据必须在 8字节及以上
        // icmp类型必须为 ICMP_ECHO_REPLY
        if ipv4_header.protocol != 1 || net_layer_data.len() < 8 || net_layer_data[0] != 0 { return false }

        let validation = aes_rand.validate_gen_v4_u32_without_sport(ipv4_header.dest_addr, ipv4_header.source_addr);
        if net_layer_data[4] != validation[6] || net_layer_data[5] != validation[7] { return false }
        if net_layer_data[6] != validation[10] || net_layer_data[7] != validation[11] { return false }
        true
    }

    fn validate_packet_v4(&self, _data_link_header: &[u8], ipv4_header: &Ipv4PacketU32, net_layer_data: &[u8], aes_rand: &AesRand) -> (bool, u16, Option<u32>) {

        if ipv4_header.protocol != 1 || net_layer_data.len() < 8 {
            // 如果 ipv4首部 中的 协议号 对应的不是 icmp_v4
            // 网络层数据必须在 8字节及以上
            return (false, 0, None)
        }

        if net_layer_data[0] == 0 {
            // 如果icmp类型为  ICMP_ECHO_REPLY
            let validation = aes_rand.validate_gen_v4_u32_without_sport(ipv4_header.dest_addr, ipv4_header.source_addr);

            if net_layer_data[4] != validation[6] || net_layer_data[5] != validation[7] {
                return (false, 0, None)
            }
            if net_layer_data[6] != validation[10] || net_layer_data[7] != validation[11] {
                return (false, 0, None)
            }

            // 验证通过, none表示非内层源地址
            (true, 0, None)
        } else {
            // 如果icmp类型为 其他类型
            match net_layer_data[0] {
                3 | 4 | 5 | 11 => {
                    // 如果是目的不可达, 源端抑制, 重定向, 超时
                    if net_layer_data.len() < 36 {
                        // 如果存在内层ipv4数据包, 网络层的总长度应至少为 外层icmp报头(8字节) + 内层ipv4报头(20字节) + 内层icmp报头(8字节)
                        // 注意: icmp_v4错误报文返回 网络层首部 和 原始数据包(比网络层更高层)前8个字节
                        // 8 + 20 + 8 = 36
                        return (false, 0, None)
                    }

                    let inner_ip_header_len = ((net_layer_data[8] & 0b_0000_1111u8) as usize) * 4;
                    if net_layer_data.len() < (16 + inner_ip_header_len) {
                        // 如果存在内层ipv4数据包, 网络层的总长度应至少为 外层icmp报头(8字节) + 内层ipv4报头 + 内层icmp报头(8字节)
                        return (false, 0, None)
                    }

                    // 提取内部ipv4数据包中的地址
                    let inner_ip = &net_layer_data[8..];

                    let inner_src_ip = Ipv4PacketU32::get_source_addr(inner_ip);
                    let inner_dest_ip = Ipv4PacketU32::get_dest_addr(inner_ip);

                    // 使用icmp错误信息中包含的ipv4首部重新生成验证信息
                    let validation = aes_rand.validate_gen_v4_u32_without_sport(
                        inner_src_ip, inner_dest_ip);

                    // 取出内部数据包中包含的icmp_v4报文
                    let icmp4 = &inner_ip[inner_ip_header_len..];

                    if icmp4[4] != validation[6] || icmp4[5] != validation[7] {
                        return (false, 0, None)
                    }
                    if icmp4[6] != validation[10] || icmp4[7] != validation[11] {
                        return (false, 0, None)
                    }

                    // 注意此处返回的 源ip 为内层数据包的 目的地址, 即探测地址
                    (true, 0, Some(inner_dest_ip))
                }
                _ => { (false, 0, None) }
            }
        }
    }

    fn print_header(&self) -> Vec<String> {
        //  注意顺序
        let mut output_data = Vec::with_capacity(self.fields_flag.len);
        push_fields_name!(self; output_data; source_addr, outer_source_addr, icmp_type, icmp_code, identifier, sequence_num, classification);
        
        if self.print_ipv4_packet {
            output_data.extend(Ipv4PacketU32::print_header());
        }
        
        output_data
    }

    fn process_packet_v4(&self, _header: &PacketHeader, _data_link_header: &[u8], ipv4_header: &Ipv4PacketU32, net_layer_data: &[u8], inner_src_ip:Option<u32>) -> (bool, Vec<String>) {

        let mut output_data = Vec::with_capacity(self.fields_flag.len);

        let success_flag;
        if let Some(ip) = inner_src_ip {
            // 如果有 内层ip
            success_flag = false;
            push_fields_val!(self; output_data; (source_addr, Ipv4Addr::from(ip)), (outer_source_addr, Ipv4Addr::from(ipv4_header.source_addr)));
        } else {
            // 如果没有内层ip, 直接使用外层ip
            success_flag = true;
            push_fields_val!(self; output_data; (source_addr, Ipv4Addr::from(ipv4_header.source_addr)), (outer_source_addr, ""));
        }

        if self.fields_flag.icmp_fields_exist {
            // 使用网络层数据生成icmp_v6报头
            if success_flag {
                // 正常响应
                push_fields_val!(self; output_data;
                    (icmp_type, net_layer_data[0]),
                    (icmp_code, net_layer_data[1]),
                    (identifier, ((net_layer_data[4] as u16) << 8) | (net_layer_data[5] as u16)),
                    (sequence_num, ((net_layer_data[6] as u16) << 8) | (net_layer_data[7] as u16)));
            } else {
                // icmp 错误报文
                push_fields_val!(self; output_data;
                    (icmp_type, net_layer_data[0]),
                    (icmp_code, net_layer_data[1]),
                    (identifier, ""),
                    (sequence_num, ""));
            }
        }

        if self.fields_flag.classification {
            if net_layer_data[0] == 0 {
                output_data.push(String::from("echo_reply"));
            } else {
                let classification = IcmpV4Fields::parse_icmp4_classification(net_layer_data[0], net_layer_data[1]);
                output_data.push(classification);
            }
        }

        if self.print_ipv4_packet {
            output_data.extend(ipv4_header.print())
        }
        
        (success_flag, output_data)
    }
}