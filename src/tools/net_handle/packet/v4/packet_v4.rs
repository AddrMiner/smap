use std::net::Ipv4Addr;

#[allow(dead_code)]
pub struct Ipv4Packet {

    pub ihl:u8,                     // 首部长度
    pub tos:u8,                     // 服务类型
    pub total_len:u16,              // 总长度
    pub id:u16,                     // 标识

    pub rf:u8,                     // 保留的片段标志
    pub df:u8,                    // 标志字段中间位 DF=1：不能分片，DF=0：允许分片
    pub mf:u8,                    // 标志字段最后一位

    pub offset:u16,                 // 片偏移

    pub ttl:u8,                     // 生存时间
    pub protocol:u8,                // 协议
    pub header_check_sum:u16,       // 头部校验和


    pub source_addr:Ipv4Addr,           // 源地址
    pub dest_addr:Ipv4Addr,             // 目的地址

}

impl Ipv4Packet {

    #[allow(dead_code)]
    pub fn  parse_ipv4_packet(d:& [u8]) -> Ipv4Packet {


        // 注意: 位运算 和 标准库方法提取字段各有不同的开销, 位运算的最大开销是类型转换, 标准库的开销是构造新数组和抽象层开销
        // 建议位数较少时使用位运算, 位数较多时使用标准库函数

        Ipv4Packet {
            ihl: d[0] & 0b_0000_1111u8,
            tos: d[1],

            total_len: ((d[2] as u16) << 8) | (d[3] as u16),
            //total_len: u16::from_be_bytes([d[2], d[3]]),

            id: ((d[4] as u16) << 8) | (d[5] as u16),
            //id:u16::from_be_bytes([d[4], d[5]]),

            rf: (d[6] >> 7) & 1 ,
            df: (d[6] >> 6) & 1 ,        //  1 为真
            mf: (d[6] >> 5) & 1 ,

            offset: ((( d[6] & 0b_000_11111u8 ) as u16) << 8) | ( d[7] as u16 ),
            //offset: u16::from_be_bytes([d[6] & 0b_000_11111u8, d[7]]),

            ttl: d[8],
            protocol: d[9],
            header_check_sum: ((d[10] as u16) << 8) | (d[11] as u16),
            //header_check_sum:u16::from_be_bytes([d[10], d[11]]),

            source_addr:Ipv4Addr::from([d[12], d[13], d[14], d[15]]),
            dest_addr:Ipv4Addr::from([d[16], d[17], d[18], d[19]]),

        }



    }


    #[allow(dead_code)]
    pub fn get_source_addr(d:& [u8]) -> Ipv4Addr {
        Ipv4Addr::from([d[12], d[13], d[14], d[15]])
    }

    #[allow(dead_code)]
    pub fn get_dest_addr(d:& [u8]) -> Ipv4Addr {
        Ipv4Addr::from([d[16], d[17], d[18], d[19]])
    }


}