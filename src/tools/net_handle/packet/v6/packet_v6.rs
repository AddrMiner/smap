use std::net::Ipv6Addr;

#[derive(Debug)]
pub struct Ipv6Packet {

    pub traffic_class:u8,           // 通信类型
    pub flow_label:u32,             // 流标签
    pub payload_len:u16,            // 载荷长度
    pub next_header:u8,             // 下一头部
    pub hop_limit:u8,               // 跳数限制

    pub source_addr:Ipv6Addr,           // 源地址
    pub dest_addr:Ipv6Addr,             // 目的地址

}

impl Ipv6Packet {


    #[allow(dead_code)]
    pub fn parse_ipv6_packet(d:& [u8]) -> Ipv6Packet {


        Ipv6Packet {
            traffic_class: (d[0] << 4) | (d[1] >> 4),
            flow_label: (((d[1] << 4) as u32) << 12) | ((d[2] as u32) << 8) | (d[3] as u32) ,
            payload_len: ((d[4] as u16) << 8) | (d[5] as u16),
            next_header: d[6],
            hop_limit: d[7],

            source_addr:Ipv6Addr::from([d[8], d[9], d[10],d[11],
                d[12],d[13],d[14],d[15],
                d[16],d[17],d[18],d[19],
                d[20],d[21],d[22], d[23]]),

            dest_addr:Ipv6Addr::from([d[24], d[25], d[26],d[27],
                d[28],d[29],d[30],d[31],
                d[32],d[33],d[34],d[35],
                d[36],d[37],d[38], d[39]]),

        }
    }


    /// 获取 ipv6 源地址
    #[allow(dead_code)]
    pub fn get_source_addr(d:& [u8]) -> Ipv6Addr {

        Ipv6Addr::from([d[8], d[9], d[10], d[11],
            d[12], d[13], d[14], d[15],
            d[16], d[17], d[18], d[19],
            d[20], d[21], d[22], d[23],])
    }

    /// 获取 ipv6 目的地址
    #[allow(dead_code)]
    pub fn get_dest_addr(d:& [u8]) -> Ipv6Addr {

        Ipv6Addr::from([d[24], d[25], d[26],d[27],
            d[28],d[29],d[30],d[31],
            d[32],d[33],d[34],d[35],
            d[36],d[37],d[38], d[39]])
    }



}