

pub struct Ipv4PacketU32 {

    pub ihl:u8,                     // 首部长度
    pub tos:u8,                     // 服务类型
    pub total_len:u16,              // 总长度

    // 6位标识唯一地标识主机发送的每一个数据报。其初始值由系统随机生成；每发送一个数据报，其值就加1。
    // 该值在数据报分片时被复制到每个分片中，因此同一个数据报的所有分片都具有相同的标识值。
    pub id:u16,                     // 标识

    pub rf:u8,                     // 保留的片段标志
    pub df:u8,                    // 标志字段中间位 DF=1：不能分片，DF=0：允许分片
    pub mf:u8,                    // 标志字段最后一位

    pub offset:u16,                 // 片偏移

    pub ttl:u8,                     // 生存时间
    pub protocol:u8,                // 协议
    pub header_check_sum:u16,       // 头部校验和


    pub source_addr:u32,           // 源地址
    pub dest_addr:u32,             // 目的地址

}

impl Ipv4PacketU32 {
    
    pub fn print_header() -> Vec<String> {
        vec![
            "ipv4_ihl".to_string(),
            "ipv4_tos".to_string(),
            "ipv4_total_len".to_string(),
            
            "ipv4_id".to_string(),
            
            "ipv4_rf".to_string(),
            "ipv4_df".to_string(),
            "ipv4_mf".to_string(),
            
            "ipv4_offset".to_string(),
            
            "ipv4_ttl".to_string(),
            "ipv4_protocol".to_string(),
            "ipv4_header_check_sum".to_string(),
            
            "ipv4_source_addr".to_string(),
            "ipv4_dest_addr".to_string()
        ]
    }
    
    pub fn print(&self) -> Vec<String> {
        vec![
            self.ihl.to_string(), 
            self.tos.to_string(), 
            self.total_len.to_string(),
            
            self.id.to_string(),
            
            self.rf.to_string(),
            self.df.to_string(),
            self.mf.to_string(),
            
            self.offset.to_string(),
            
            self.ttl.to_string(),
            self.protocol.to_string(),
            self.header_check_sum.to_string(),
            
            self.source_addr.to_string(),
            self.dest_addr.to_string()
        ]
    }


    /// 从ipv4首部计算校验和
    pub fn get_check_sum_from_buf(ipv4_header:&[u8]) -> [u8; 2] {

        let mut sum:u32 = 0;

        for i in 0..10 {

            let z = 2 * i;
            sum += u16::from_be_bytes([ipv4_header[z], ipv4_header[z+1]]) as u32;
        }

        while sum > 65535  {
            sum = (sum >> 16) + (sum & 0xFFFF);
        }

        let sum = (!sum) as u16;
        sum.to_be_bytes()
    }




    /// 将ipv4首部转换为字节数组 地址
    /// 警告: 校验和部分将直接置为 0
    pub fn get_u8_vec_without_addr(&self) -> [u8; 12] {

        // 版本号
        let ver = 4u8;

        let first_byte = (ver << 4) | self.ihl;

        let total_len_bytes = self.total_len.to_be_bytes();
        let id_bytes = self.id.to_be_bytes();

        let seventh_byte = (self.rf << 7) | (self.df << 6) | (self.mf << 5) | ((self.offset >> 8) as u8);

        let eighth_byte = ((self.offset << 8) >> 8) as u8;

        [
            first_byte,  self.tos,    total_len_bytes[0], total_len_bytes[1],
            id_bytes[0], id_bytes[1], seventh_byte,       eighth_byte,
            self.ttl,    self.protocol,          0,                0
        ]

    }



    pub fn  parse_ipv4_packet(d:& [u8]) -> Self {

        Self {
            ihl: d[0] & 0b_0000_1111u8,
            tos: d[1],

            total_len: ((d[2] as u16) << 8) | (d[3] as u16),
            //total_len: u16::from_be_bytes([d[2], d[3]]),

            id: ((d[4] as u16) << 8) | (d[5] as u16),
            //id:u16::from_be_bytes([d[4], d[5]]),

            rf: (d[6] >> 7) & 1 ,
            df: (d[6] >> 6) & 1 ,        //  1 为真
            mf: (d[6] >> 5) & 1 ,

            offset: (((d[6] & 0b_000_11111u8) as u16) << 8) | ( d[7] as u16 ),
            ttl: d[8],
            protocol: d[9],

            header_check_sum: ((d[10] as u16) << 8) | (d[11] as u16),
            //header_check_sum:u16::from_be_bytes([d[10], d[11]]),


            // source_addr: ((d[12] as u32) << 24) | ((d[13] as u32) << 16) | ((d[14] as u32) << 8) | (d[15] as u32),
            // dest_addr: ((d[16] as u32) << 24) | ((d[17] as u32) << 16) | ((d[18] as u32) << 8) | (d[19] as u32),

            source_addr: u32::from_be_bytes([d[12], d[13], d[14], d[15]]),
            dest_addr: u32::from_be_bytes([d[16], d[17], d[18], d[19]])
        }
    }

    pub fn get_source_addr(d:& [u8]) -> u32 {
        u32::from_be_bytes([d[12], d[13], d[14], d[15]])
    }

    pub fn get_dest_addr(d:& [u8]) -> u32 {
        u32::from_be_bytes([d[16], d[17], d[18], d[19]])
    }

    #[allow(dead_code)]
    pub fn  parse_ipv4_packet_from_source_addr(d:& [u8], source_addr:u32) -> Self {

        Self {
            ihl: d[0] & 0b_0000_1111u8,
            tos: d[1],

            total_len: ((d[2] as u16) << 8) | (d[3] as u16),
            //total_len: u16::from_be_bytes([d[2], d[3]]),

            id: ((d[4] as u16) << 8) | (d[5] as u16),
            //id:u16::from_be_bytes([d[4], d[5]]),

            rf: (d[6] >> 7) & 1 ,
            df: (d[6] >> 6) & 1 ,        //  1 为真
            mf: (d[6] >> 5) & 1 ,

            offset: (((d[6] & 0b_000_11111u8) as u16) << 8) | ( d[7] as u16 ),
            ttl: d[8],
            protocol: d[9],

            header_check_sum: ((d[10] as u16) << 8) | (d[11] as u16),
            //header_check_sum:u16::from_be_bytes([d[10], d[11]]),


            // source_addr: ((d[12] as u32) << 24) | ((d[13] as u32) << 16) | ((d[14] as u32) << 8) | (d[15] as u32),
            // dest_addr: ((d[16] as u32) << 24) | ((d[17] as u32) << 16) | ((d[18] as u32) << 8) | (d[19] as u32),

            source_addr,
            dest_addr: u32::from_be_bytes([d[16], d[17], d[18], d[19]])
        }
    }





}