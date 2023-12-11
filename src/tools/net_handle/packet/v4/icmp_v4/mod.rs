pub mod fields;

pub struct IcmpV4Packet {

    // 报文类型
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


impl IcmpV4Packet {


    /// 计算校验值并赋值给自身, 计算过程中未使用校验和字段, 原有校验和字段被替换
    #[allow(dead_code)]
    pub fn count_check_sum(&mut self) {

        let mut sum:u32 = 0;

        sum += (((self.icmp_type as u16) << 8) | (self.code as u16)) as u32;

        // 因为 检验和为0所以跳过

        sum += self.identifier as u32;

        sum += self.sequence_number as u32;

        // 将结果的高16位与低16位相加
        while sum > 65535  {
            sum = (sum >> 16) + (sum & 0xFFFF);
        }

        self.check_sum =  (!sum) as u16
    }

    pub fn get_check_sum(icmp_header_data:&[u8]) -> [u8;2] {

        let mut sum = 0u32;

        let icmp_header_data_len = icmp_header_data.len();
        let icmp_index = icmp_header_data_len / 2 ;
        let is_odd = icmp_header_data_len % 2 == 1;

        for i in 0..icmp_index {
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
        let sequence_number_bytes = self.sequence_number.to_be_bytes();

        [
            self.icmp_type,      self.code,           check_sum_bytes[0],       check_sum_bytes[1],
            identifier_bytes[0], identifier_bytes[1], sequence_number_bytes[0], sequence_number_bytes[1]
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


pub const ICMP_UNREACH:[&str; 16] = [
    "network unreachable",
    "host unreachable",
    "protocol unreachable",
    "port unreachable",
    "fragments required",
    "source route failed",
    "network unknown",
    "host unknown",
    "source host isolated",
    "network admin. prohibited",
    "host admin. prohibited",
    "network unreachable TOS",
    "host unreachable TOS",
    "communication admin. prohibited",
    "host presdence violation",
    "precedence cutoff"
];