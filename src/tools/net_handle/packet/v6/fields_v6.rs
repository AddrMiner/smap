use crate::tools::net_handle::packet::v6::packet_v6_u128::Ipv6PacketU128;

#[allow(dead_code)]
pub struct Ipv6Fields {

    pub traffic_class:bool,           // 通信类型
    pub flow_label:bool,             // 流标签
    pub payload_len:bool,            // 载荷长度
    pub next_header:bool,             // 下一头部
    pub hop_limit:bool,               // 跳数限制

    pub source_addr:bool,           // 源地址
    pub dest_addr:bool,             // 目的地址

}



impl Ipv6Fields {

    #[allow(dead_code)]
    pub fn get_fields(&self, ipv6_header:&Ipv6PacketU128) -> Vec<String> {

        let mut output_data  = vec![];

        if self.traffic_class {
            output_data.push(ipv6_header.traffic_class.to_string());
        }

        if self.flow_label {
            output_data.push(ipv6_header.flow_label.to_string());
        }

        if self.payload_len {
            output_data.push(ipv6_header.payload_len.to_string());
        }

        if self.next_header {
            output_data.push(ipv6_header.next_header.to_string());
        }

        if self.hop_limit {
            output_data.push(ipv6_header.hop_limit.to_string());
        }

        if self.source_addr {
            output_data.push(ipv6_header.source_addr.to_string());
        }

        if self.dest_addr {
            output_data.push(ipv6_header.source_addr.to_string());
        }

        output_data
    }

    #[allow(dead_code)]
    pub fn print_header(&self) -> Vec<String> {

        let mut output_data  = vec![];

        if self.traffic_class {
            output_data.push("traffic_class".to_string());
        }

        if self.flow_label {
            output_data.push("flow_label".to_string());
        }

        if self.payload_len {
            output_data.push("payload_len".to_string());
        }

        if self.next_header {
            output_data.push("next_header".to_string());
        }

        if self.hop_limit {
            output_data.push("hop_limit".to_string());
        }

        if self.source_addr {
            output_data.push("source_addr".to_string());
        }

        if self.dest_addr {
            output_data.push("dest_addr".to_string());
        }

        output_data
    }

}