use crate::tools::net_handle::packet::tcp::TcpPacket;

impl TcpPacket {

    pub fn get_check_sum_v4(source_ip:&[u8], dest_ip:&[u8], tcp_header_data_len:u32, tcp_header_data:&[u8]) -> [u8;2] {

        // 注意这里 把tcp协议号 设为初始值
        let mut sum:u32 = 6u32;

        // 伪首部
        sum += u16::from_be_bytes([source_ip[0], source_ip[1]]) as u32;
        sum += u16::from_be_bytes([source_ip[2], source_ip[3]]) as u32;
        sum += u16::from_be_bytes([dest_ip[0], dest_ip[1]]) as u32;
        sum += u16::from_be_bytes([dest_ip[2], dest_ip[3]]) as u32;
        sum += tcp_header_data_len;


        let tcp_data_len = tcp_header_data.len();
        let tcp_data_index = tcp_data_len / 2 ;
        let is_odd = tcp_data_len % 2 == 1;

        for i in 0..tcp_data_index {
            let z = i * 2;
            sum += u16::from_be_bytes([tcp_header_data[z],  tcp_header_data[z+1]]) as u32;
        }

        if is_odd {
            sum += u16::from_be_bytes([tcp_header_data[tcp_data_len - 1], 0]) as u32;
        }

        while sum > 65535  {
            sum = (sum >> 16) + (sum & 0xFFFF);
        }

        let check_sum = (!sum) as u16;
        check_sum.to_be_bytes()
    }
}