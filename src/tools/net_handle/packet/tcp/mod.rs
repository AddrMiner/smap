

pub mod v4;
pub mod v6;
pub mod fields;
pub mod opt;


pub struct TcpPacket {

    pub sport:u16,      // 源端口
    pub dport:u16,      // 目的端口

    pub sequence_num:u32,   // 顺序号
    pub ack_num:u32,        // 应答号

    pub header_len:u8,      // 首部长度

    pub urg:u8,             // 紧急标识位
    pub ack:u8,             // 应答标识位 应答号之前的数据接收成功
    pub psh:u8,             // 不进行缓存直接推送到应用的标志位
    pub rst:u8,             // 标志重连接的标志位
    pub syn:u8,             // 同步顺序号以初始化连接的标志位
    pub fin:u8,             // 发送数据完毕的标志位（表明不会再发送数据过来）

    pub window_size:u16,    // 窗口大小
    pub check_sum:u16,      // 校验和
    pub urgent_pointer:u16, // 紧急指针

}


impl TcpPacket {

    pub fn from(d:& [u8]) -> TcpPacket {

        TcpPacket {
            sport: ((d[0] as u16) << 8) | (d[1] as u16),
            dport: ((d[2] as u16) << 8) | (d[3] as u16),

            sequence_num: u32::from_be_bytes([d[4], d[5], d[6], d[7]]),
            ack_num: u32::from_be_bytes([d[8], d[9], d[10], d[11]]),

            header_len: d[12] >> 4,

            urg: (d[13] >> 5) & 1,
            ack: (d[13] >> 4) & 1,
            psh: (d[13] >> 3) & 1,
            rst: (d[13] >> 2) & 1,
            syn: (d[13] >> 1) & 1,
            fin:  d[13] & 1,

            window_size: ((d[14] as u16) << 8) | (d[15] as u16),
            check_sum: ((d[16] as u16) << 8) | (d[17] as u16),
            urgent_pointer: ((d[18] as u16) << 8) | (d[19] as u16),
        }
    }


    pub fn get_u8_vec_after_ack(&self) -> [u8;8] {

        let twelfth_byte = self.header_len << 4;
        let thirteenth_byte = (self.urg << 5) | (self.ack << 4) | (self.psh << 3) | (self.rst << 2) | (self.syn << 1) | self.fin;

        let window_size_bytes = self.window_size.to_be_bytes();
        let urgent_pointer_bytes = self.urgent_pointer.to_be_bytes();

        [
            twelfth_byte,       thirteenth_byte,    window_size_bytes[0],    window_size_bytes[1],
            0,                                0, urgent_pointer_bytes[0], urgent_pointer_bytes[1],
        ]
    }

    pub fn get_u8_vec_after_sequence(&self) -> [u8;12] {

        let ack_num_bytes = self.ack_num.to_be_bytes();

        let twelfth_byte = self.header_len << 4;
        let thirteenth_byte = (self.urg << 5) | (self.ack << 4) | (self.psh << 3) | (self.rst << 2) | (self.syn << 1) | self.fin;

        let window_size_bytes = self.window_size.to_be_bytes();
        let urgent_pointer_bytes = self.urgent_pointer.to_be_bytes();

        [
            ack_num_bytes[0],      ack_num_bytes[1],        ack_num_bytes[2],        ack_num_bytes[3],
                twelfth_byte,       thirteenth_byte,    window_size_bytes[0],    window_size_bytes[1],
                           0,                     0, urgent_pointer_bytes[0], urgent_pointer_bytes[1],
        ]
    }

    /// 返回 mss选项字节数组, 包括 kind, length (注意: 需要手动修改 负载长度)
    pub fn get_mss_option() -> [u8; 4] {
        // 注意: 需要手动修改 负载长度
        // 此函数只提供 mss 字段字节数组

        let tcp_option_kind:u8 = 2;
        let tcp_option_length:u8 = 4;   // 注意 长度包括kind, length字段

        let mss_max_segment:u16 = 1460;
        let mss_info_bytes = mss_max_segment.to_be_bytes();

        [
              tcp_option_kind, tcp_option_length,
            mss_info_bytes[0], mss_info_bytes[1],
        ]
    }


    #[allow(dead_code)]
    pub fn get_u8_vec(&self) -> [u8;20] {

        let sport_bytes = self.sport.to_be_bytes();
        let dport_bytes = self.dport.to_be_bytes();

        let sequence_num_bytes = self.sequence_num.to_be_bytes();
        let ack_num_bytes = self.ack_num.to_be_bytes();

        let twelfth_byte = self.header_len << 4;
        let thirteenth_byte = (self.urg << 5) | (self.ack << 4) | (self.psh << 3) | (self.rst << 2) | (self.syn << 1) | self.fin;

        let window_size_bytes = self.window_size.to_be_bytes();
        let check_sum_bytes = self.check_sum.to_be_bytes();
        let urgent_pointer_bytes = self.urgent_pointer.to_be_bytes();

        [
                   sport_bytes[0],        sport_bytes[1],          dport_bytes[0],          dport_bytes[1],
            sequence_num_bytes[0], sequence_num_bytes[1],   sequence_num_bytes[2],   sequence_num_bytes[3],
                 ack_num_bytes[0],      ack_num_bytes[1],        ack_num_bytes[2],        ack_num_bytes[3],
                     twelfth_byte,       thirteenth_byte,    window_size_bytes[0],    window_size_bytes[1],
               check_sum_bytes[0],    check_sum_bytes[1], urgent_pointer_bytes[0], urgent_pointer_bytes[1],
        ]
    }

}
