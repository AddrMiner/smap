pub mod fields;

#[derive(Debug)]
pub struct IcmpV6Packet {

    // icmp_v6报文的类型, 当取值介于 0 到 127 之间时，表示该报文为错误报文（如目的不可达、超时等）, 当取值在 128 到 255 之间时，则表示该报文为信息报文
    pub icmp_type: u8,

    // 表示此消息类型(Type)细分的类型，具体区分每种消息类型的错误信息，如目的不可达可能是防火墙导致的，也可能是路由错误导致的
    pub code:u8,

    // 校验和
    pub check_sum:u16,

    // 用于标识本ICMP进程
    pub identifier:u16,

    // 用于标识请求、响应报文
    pub sequence_number:u16,
}


impl IcmpV6Packet {

    #[inline]
    pub fn get_check_sum(source_ip:&[u8], dest_ip:&[u8], len:u32, icmp_header_data:&[u8]) -> [u8;2] {

        // 注意: 序列号默认为 0

        // 注意这里 把 icmp_v6协议号 设为初始值
        let mut sum:u32 = 58u32;

        for i in 0..8 {

            let z = i * 2;
            sum += u16::from_be_bytes([source_ip[z], source_ip[z + 1]]) as u32;
            sum += u16::from_be_bytes([dest_ip[z], dest_ip[z + 1]]) as u32;
            // i=0     0, 1
            // i=1     2, 3
            // i=2     4, 5
            // i=3     6, 7
            // ...
            // i=7     14, 15
        }

        sum += len;

        let icmp_header_data_len = icmp_header_data.len();
        let icmp_header_data_index = icmp_header_data_len / 2 ;
        let is_odd = icmp_header_data_len % 2 == 1;

        for i in 0..icmp_header_data_index {
            let z = i * 2;
            sum += u16::from_be_bytes([icmp_header_data[z],  icmp_header_data[z+1]]) as u32;
        }

        if is_odd {
            sum += u16::from_be_bytes([icmp_header_data[icmp_header_data_len - 1], 0]) as u32;
        }

        while sum > 65535  {
            sum = (sum >> 16) + (sum & 0xFFFF);
        }

        let check_sum = (!sum) as u16;
        check_sum.to_be_bytes()
    }



    #[allow(dead_code)]
    pub fn get_u8_vec(&self) -> [u8; 8] {

        let check_sum_bytes = self.check_sum.to_be_bytes();
        let identifier_bytes = self.identifier.to_be_bytes();

        [
            self.icmp_type,      self.code,          check_sum_bytes[0], check_sum_bytes[1],
            // 序列号填充为0
            identifier_bytes[0], identifier_bytes[1],                 0,                  0,
        ]

    }

    #[allow(dead_code)]
    pub fn new(d:& [u8]) -> Self {


        Self {
            icmp_type: d[0],
            code: d[1],
            check_sum: ((d[2] as u16) << 8) | (d[3] as u16),
            identifier: ((d[4] as u16) << 8) | (d[5] as u16),
            sequence_number: ((d[6] as u16) << 8) | (d[7] as u16),
        }

    }


}

