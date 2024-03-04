


pub struct Ipv6PacketU128 {

    pub traffic_class:u8,           // 通信类型
    pub flow_label:u32,             // 流标签
    pub payload_len:u16,            // 载荷长度  除了基本首部以外的字节数（所有扩展首部字节数都算在内）
    pub next_header:u8,             // 下一头部
    pub hop_limit:u8,               // 跳数限制

    pub source_addr:u128,           // 源地址
    pub dest_addr:u128,             // 目的地址
}


impl Ipv6PacketU128 {

    pub fn print_header() -> Vec<String> {
        vec![
            "ipv6_traffic_class".to_string(),
            "ipv6_flow_label".to_string(),
            "ipv6_payload_len".to_string(),
            "ipv6_next_header".to_string(),
            "ipv6_hop_limit".to_string(),

            "ipv6_source_addr".to_string(),
            "ipv6_dest_addr".to_string(),
        ]
    }

    pub fn print(&self) -> Vec<String> {
        vec![
            self.traffic_class.to_string(),
            self.flow_label.to_string(),
            self.payload_len.to_string(),
            self.next_header.to_string(),
            self.hop_limit.to_string(),

            self.source_addr.to_string(),
            self.dest_addr.to_string()
        ]
    }

    pub fn get_u8_vec_before_payload_len(&self) -> [u8; 4] {

        // 版本号
        let ver = 6u8;

        let first_byte = (ver << 4) | (self.traffic_class >> 4);
        let second_byte = (self.traffic_class << 4) | ((self.flow_label >> 16) as u8);
        let third_byte = ((self.flow_label << 16) >> 24) as u8;
        let fourth_byte = ((self.flow_label << 24) >> 24) as u8;

        [
            first_byte,           second_byte,          third_byte,           fourth_byte,
        ]

    }

    pub fn get_u8_vec_without_addr(&self) -> [u8; 8] {

        // 版本号
        let ver = 6u8;

        let first_byte = (ver << 4) | (self.traffic_class >> 4);
        let second_byte = (self.traffic_class << 4) | ((self.flow_label >> 16) as u8);
        let third_byte = ((self.flow_label << 16) >> 24) as u8;
        let fourth_byte = ((self.flow_label << 24) >> 24) as u8;

        let payload_len_bytes = self.payload_len.to_be_bytes();

        [
            first_byte,           second_byte,          third_byte,           fourth_byte,
            payload_len_bytes[0], payload_len_bytes[1], self.next_header,     self.hop_limit,
        ]

    }


    #[allow(dead_code)]
    pub fn get_u8_vec(&self) -> [u8; 40] {

        // 版本号
        let ver = 6u8;

        let first_byte = (ver << 4) | (self.traffic_class >> 4);
        let second_byte = (self.traffic_class << 4) | ((self.flow_label >> 16) as u8);
        let third_byte = ((self.flow_label << 16) >> 24) as u8;
        let fourth_byte = ((self.flow_label << 24) >> 24) as u8;

        let payload_len_bytes = self.payload_len.to_be_bytes();
        let source_addr_bytes = self.source_addr.to_be_bytes();
        let dest_addr_bytes = self.dest_addr.to_be_bytes();

        [

            first_byte,           second_byte,          third_byte,           fourth_byte,
            payload_len_bytes[0], payload_len_bytes[1], self.next_header,     self.hop_limit,

            source_addr_bytes[0], source_addr_bytes[1], source_addr_bytes[2], source_addr_bytes[3],
            source_addr_bytes[4], source_addr_bytes[5], source_addr_bytes[6], source_addr_bytes[7],
            source_addr_bytes[8], source_addr_bytes[9], source_addr_bytes[10],source_addr_bytes[11],
            source_addr_bytes[12],source_addr_bytes[13],source_addr_bytes[14],source_addr_bytes[15],

            dest_addr_bytes[0],   dest_addr_bytes[1],   dest_addr_bytes[2],   dest_addr_bytes[3],
            dest_addr_bytes[4],   dest_addr_bytes[5],   dest_addr_bytes[6],   dest_addr_bytes[7],
            dest_addr_bytes[8],   dest_addr_bytes[9],   dest_addr_bytes[10],  dest_addr_bytes[11],
            dest_addr_bytes[12],  dest_addr_bytes[13],  dest_addr_bytes[14],  dest_addr_bytes[15]

        ]

    }


    pub fn parse_ipv6_packet(d:& [u8]) -> Ipv6PacketU128 {


        Ipv6PacketU128 {
            traffic_class: (d[0] << 4) | (d[1] >> 4),
            flow_label: (((d[1] << 4) as u32) << 12) | ((d[2] as u32) << 8) | (d[3] as u32) ,
            payload_len: ((d[4] as u16) << 8) | (d[5] as u16),
            next_header: d[6],
            hop_limit: d[7],

            source_addr: u128::from_be_bytes([d[8], d[9], d[10], d[11],
                                                    d[12], d[13], d[14], d[15],
                                                    d[16], d[17], d[18], d[19],
                                                    d[20], d[21], d[22], d[23],]),

            dest_addr :  u128::from_be_bytes([d[24], d[25], d[26], d[27],
                                                    d[28], d[29], d[30], d[31],
                                                    d[32], d[33], d[34], d[35],
                                                    d[36], d[37], d[38], d[39], ]),

            // source_addr: ((d[8] as u128) << 120) | ((d[9] as u128) << 112) | ((d[10] as u128) << 104) | ((d[11] as u128) << 96)
            //             | ((d[12] as u128) << 88) | ((d[13] as u128) << 80) | ((d[14] as u128) << 72) | ((d[15] as u128) << 64)
            //             | ((d[16] as u128) << 56) | ((d[17] as u128) << 48) | ((d[18] as u128) << 40) | ((d[19] as u128) << 32)
            //             | ((d[20] as u128) << 24) | ((d[21] as u128) << 16) | ((d[22] as u128) << 8) | (d[23] as u128),



            // dest_addr: ((d[24] as u128) << 120) | ((d[25] as u128) << 112) | ((d[26] as u128) << 104) | ((d[27] as u128) << 96)
            //     | ((d[28] as u128) << 88) | ((d[29] as u128) << 80) | ((d[30] as u128) << 72) | ((d[31] as u128) << 64)
            //     | ((d[32] as u128) << 56) | ((d[33] as u128) << 48) | ((d[34] as u128) << 40) | ((d[35] as u128) << 32)
            //     | ((d[36] as u128) << 24) | ((d[37] as u128) << 16) | ((d[38] as u128) << 8) | (d[39] as u128),

        }
    }

    /// 获取 ipv6 源地址
    pub fn get_source_addr(d:& [u8]) -> u128 {

        u128::from_be_bytes([d[8], d[9], d[10], d[11],
            d[12], d[13], d[14], d[15],
            d[16], d[17], d[18], d[19],
            d[20], d[21], d[22], d[23],])
    }

    /// 获取 ipv6 目的地址
    pub fn get_dest_addr(d:& [u8]) -> u128 {

        u128::from_be_bytes([d[24], d[25], d[26],d[27],
            d[28],d[29],d[30],d[31],
            d[32],d[33],d[34],d[35],
            d[36],d[37],d[38], d[39]])
    }


    #[allow(dead_code)]
    pub fn parse_ipv6_packet_from_source_addr(d:& [u8], source_addr:u128) -> Ipv6PacketU128 {


        Ipv6PacketU128 {
            traffic_class: (d[0] << 4) | (d[1] >> 4),
            flow_label: (((d[1] << 4) as u32) << 12) | ((d[2] as u32) << 8) | (d[3] as u32) ,
            payload_len: ((d[4] as u16) << 8) | (d[5] as u16),
            next_header: d[6],
            hop_limit: d[7],

            source_addr,

            dest_addr :  u128::from_be_bytes([d[24], d[25], d[26], d[27],
                d[28], d[29], d[30], d[31],
                d[32], d[33], d[34], d[35],
                d[36], d[37], d[38], d[39], ]),

            // source_addr: ((d[8] as u128) << 120) | ((d[9] as u128) << 112) | ((d[10] as u128) << 104) | ((d[11] as u128) << 96)
            //             | ((d[12] as u128) << 88) | ((d[13] as u128) << 80) | ((d[14] as u128) << 72) | ((d[15] as u128) << 64)
            //             | ((d[16] as u128) << 56) | ((d[17] as u128) << 48) | ((d[18] as u128) << 40) | ((d[19] as u128) << 32)
            //             | ((d[20] as u128) << 24) | ((d[21] as u128) << 16) | ((d[22] as u128) << 8) | (d[23] as u128),



            // dest_addr: ((d[24] as u128) << 120) | ((d[25] as u128) << 112) | ((d[26] as u128) << 104) | ((d[27] as u128) << 96)
            //     | ((d[28] as u128) << 88) | ((d[29] as u128) << 80) | ((d[30] as u128) << 72) | ((d[31] as u128) << 64)
            //     | ((d[32] as u128) << 56) | ((d[33] as u128) << 48) | ((d[34] as u128) << 40) | ((d[35] as u128) << 32)
            //     | ((d[36] as u128) << 24) | ((d[37] as u128) << 16) | ((d[38] as u128) << 8) | (d[39] as u128),

        }
    }




}