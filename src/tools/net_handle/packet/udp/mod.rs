pub mod fields;
mod v4;
mod v6;


pub struct UdpPacket {

    pub sport:u16,    // 源端口
    pub dport:u16,      // 目的端口
    pub len:u16,            // UDP用户数据报的长度，其最小值是8（仅有首部）
    pub check_sum:u16,      // 校验和

}

impl UdpPacket {

    #[allow(dead_code)]
    pub fn from(d:& [u8]) -> UdpPacket {

        UdpPacket {
            sport: ((d[0] as u16) << 8) | (d[1] as u16),
            dport: ((d[2] as u16) << 8) | (d[3] as u16),
            len: ((d[4] as u16) << 8) | (d[5] as u16),
            check_sum: ((d[6] as u16) << 8) | (d[7] as u16),
        }
    }

}
