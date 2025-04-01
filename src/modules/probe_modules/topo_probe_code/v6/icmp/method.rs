use std::net::Ipv6Addr;
use chrono::Utc;
use libc::timeval;
use crate::modules::probe_modules::tools::ethernet::make_ethernet_header;
use crate::modules::probe_modules::topo_probe_code::topo_mod_v6::{CodeTopoProbeMethodV6, CodeTopoResultV6};
use crate::modules::probe_modules::topo_probe_code::v6::icmp::CodeTopoIcmpV6;
use crate::tools::encryption_algorithm::aes::AesRand;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;
use crate::tools::net_handle::packet::v6::icmp_v6::IcmpV6Packet;
use crate::tools::net_handle::packet::v6::packet_v6_u128::Ipv6PacketU128;

impl CodeTopoProbeMethodV6 for CodeTopoIcmpV6 {
    fn thread_initialize_v6(&mut self, local_mac: &MacAddress, gateway_mac: &MacAddress) {
        //  填充以太网首部字段 14字节       以太网类型为 ipv6 在以太网类型字段中的标识
        make_ethernet_header(&mut self.base_buf, local_mac, gateway_mac, 0x86DDu16);

        // 填充不连地址的ipv6首部字段  8字节
        self.base_buf.extend(Ipv6PacketU128 {
            traffic_class: 0,
            flow_label: 0,

            payload_len: self.net_layer_data_len,             // 负载长度  icmp_v6固定首部(5字节) + 自定义编码
            next_header: 58,             // 下一首部指向icmp_v6协议
            hop_limit: 64,              // 设置初始ttl

            // 这两项无效, 同时也不会传入
            source_addr: 0,
            dest_addr: 0,
        }.get_u8_vec_without_addr());
    }

    /// 警告: code原则上需要输入 3字节或以上
    fn make_packet_v6(&self, source_ip: u128, dest_prefix: u64, hop_limit: u8, code: Vec<u8>, aes_rand: &AesRand) -> Vec<u8> {
        // 按最大数据包长度设置 向量容量
        let mut packet = Vec::with_capacity(self.total_len);

        // 时间戳编码
        let send_time= (Utc::now().timestamp_millis() & 0xffff_ffff) as u32;

        // 目标前缀(8字节) | 时间戳(4字节) | 0(4字节)
        let dest_addr_raw = ((dest_prefix as u128) << 64) | ((send_time as u128) << 32);

        // 生成验证信息, 注意这里是 源地址在前
        let validation = aes_rand.validate_gen_v6_u128_without_sport(source_ip, dest_addr_raw);
        let validation = u32::from_be_bytes(validation[12..16].try_into().unwrap());

        // 目标地址: 目标前缀(8字节) | 时间戳(4字节) | 验证数据(4字节)
        let dest_ip = dest_addr_raw | (validation as u128);

        let source_ip_bytes = source_ip.to_be_bytes();
        let dest_ip_bytes = dest_ip.to_be_bytes();
        // 以太网 和 ipv6首部填充
        {
            // 以太网报头: [ 目的地址: { 0, 1, 2, 3, 4, 5}  源地址: { 6, 7, 8, 9, 10, 11 }  标识 { 12, 13 } ]
            // ipv6 报头: [ 版本: {14(1111_0000), 通信分类: {14(0000_1111), 15(1111_0000)}, 流标签:{15(0000_1111), 16, 17} ]
            //           [ 有效载荷长度: {18, 19}    下一头部: {20}   跳数限制: {21} ]
            //           [ 源地址:  { 22, 23, 24, 25,     26, 27, 28, 29,      30, 31, 32, 33,   34, 35, 36, 37 } ]
            //           [ 目的地址:{ 38, 39, 40, 41,     42, 43, 44, 45,      46, 47, 48, 49, 时间戳(4字节)   50, 51, 52, 53 验证数据(4字节) } ]

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
            // icmp报头: [ 类型: {54}  代码: {55}  校验和: {56, 57} id: {58(编码ttl), 59(编码)} 序列号: {60(编码), 61(编码)} ]
            // icmp数据: [ 62 .. <总长度]

            // 写入icmp_v6首部
            packet.extend([
                //类型              code                      check_sum字段填充为0
                128,               0,                  0,                  0,
                //  编码的ttl
                hop_limit
            ]);

            // id(后一字节), 序列号, 数据部分
            packet.extend(code);

            let check_sum_bytes = IcmpV6Packet::get_check_sum(&source_ip_bytes, &dest_ip_bytes,
                                                              // len: 5字节(icmp首部前5字节) + n字节(编码)
                                                              self.net_layer_data_len as u32, &packet[54..self.total_len]);
            packet[56] = check_sum_bytes[0];
            packet[57] = check_sum_bytes[1];
        }
        packet
    }
                                                                                                            // 目的地址, 响应地址, 编码
    fn receive_packet_v6(&self, ts: &timeval, net_layer_header: &[u8], net_layer_data: &[u8], aes_rand: &AesRand) -> Option<CodeTopoResultV6> {
        // 判断是否为icmp协议
        // 网络层数据至少包括:    icmp_v6首部(8个字节) + 内部的ipv6首部(40字节) + 内部icmp_v6首部(8个字节) = 56字节
        if net_layer_header[6] != 58 || net_layer_data.len() < 56 { return None }

        let icmp_type = net_layer_data[0];
        let icmp_code = net_layer_data[1];

        let from_destination= match icmp_type {
            // 目标不可达
            1 => true,
            // 生存时间为0(code:0) 或 分片重组超时(code:1)
            3 => match icmp_code {
                0 => false,
                _ => { return None }
            },
            _ => { return None }
        };

        // 目的地不可达 或 ttl超出限制

        // icmp_v6 首部占8个字节, 后移8个字节, 取出内部的ipv6报文
        let inner_ipv6 = &net_layer_data[8..];
        let inner_icmp_v6 = &inner_ipv6[40..];

        // 取出内部数据包中的地址信息
        let inner_src_ip = Ipv6PacketU128::get_source_addr(inner_ipv6);
        let inner_dest_ip = Ipv6PacketU128::get_dest_addr(inner_ipv6);

        // 得到 包含在目的地址中的 后32位验证数据
        let val_info = (inner_dest_ip & 0x_ffff_ffff) as u32;
        // 目标前缀 | 时间戳 | 0
        let inner_dest_ip_raw = (inner_dest_ip >> 32) << 32;

        // 使用目的地址, 源地址 生成验证信息, 注意不包含 源端口
        let validation = aes_rand.validate_gen_v6_u128_without_sport(inner_src_ip, inner_dest_ip_raw);
        let validation = u32::from_be_bytes(validation[12..16].try_into().unwrap());

        // 判断验证数据是否合法
        if val_info != validation { return None }

        // 数据包的源地址，也就是响应地址
        let res_addr = Ipv6PacketU128::get_source_addr(net_layer_header);

        // 还原时间戳
        let original_time = ((inner_dest_ip_raw >> 32) & 0x_ffff_ffff) as u32;

        // 接收时的时间戳(只取 最后32比特)
        let now_time = ((ts.tv_sec as u64) * 1000) + ((ts.tv_usec as u64) / 1000);
        // 提取 毫秒时间戳 的最后16比特
        let now_time = (now_time & 0x_ffff_ffff) as u32;

        Some(CodeTopoResultV6 {
            dest_ip: inner_dest_ip,
            responder: res_addr,
            init_ttl: inner_icmp_v6[4],

            // 是否来自目标网络(终点)
            from_destination,

            // rtt = 接收时时间戳 - 编码时间戳
            rtt: now_time - original_time,

            // 内层icmp数据中 id第一个字节以后的部分
            code: inner_icmp_v6[5..].into(),
        })
    }

    fn print_header(&self) -> Vec<String> {
        let mut output_data = Vec::with_capacity(5);
        output_data.extend(vec!["dest_ip".to_string(), "responder".to_string(), "init_ttl".to_string(), "from_destination".to_string(), "rtt".to_string()]);
        output_data
    }

    fn print_record(&self, res:&CodeTopoResultV6) -> Vec<String> {
        let mut output_data = Vec::with_capacity(5);
        output_data.extend(vec![Ipv6Addr::from(res.dest_ip).to_string(),
                                Ipv6Addr::from(res.responder).to_string(), 
                                res.init_ttl.to_string(),
                                res.from_destination.to_string(),
                                res.rtt.to_string()]);
        output_data
    }
}