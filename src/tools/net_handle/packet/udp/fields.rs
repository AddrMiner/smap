use crate::create_fields;

pub struct UdpFields {


    pub source_addr:bool,       // 源地址

    pub classification:bool,    // 类别

    pub sport:bool,             // 源端口
    pub dport:bool,             // 目的端口

    pub icmp_responder:bool,    //
    pub icmp_type:bool,         // icmp 类型
    pub icmp_code:bool,         // icmp 代码
    pub icmp_unreach:bool,

    pub udp_pkt_size:bool,      // udp 长度
    pub data:bool,              // udp 数据

    pub len:usize,
}


impl UdpFields {

    pub fn new(fields:&Vec<String>) -> Self {
        let mut fields_conf = Self {
            source_addr: false,
            classification: false,
            sport: false,
            dport: false,
            icmp_responder: false,
            icmp_type: false,
            icmp_code: false,
            icmp_unreach: false,
            udp_pkt_size: false,
            data: false,
            len: 0,
        };

        // 警告: 最后一个元素必须贴着);
        create_fields!(fields_conf; fields;
            source_addr,
            classification,
            sport,
            dport,
            icmp_responder,
            icmp_type,
            icmp_code,
            icmp_unreach,
            udp_pkt_size,
            data);

        if fields_conf.len == 0 {

            // 如果无任何字段匹配, 默认打出所有字段
            fields_conf = Self {
                source_addr: true,
                classification: true,
                sport: true,
                dport: true,
                icmp_responder: true,
                icmp_type: true,
                icmp_code: true,
                icmp_unreach: true,
                udp_pkt_size: true,
                data: true,

                len: 10,
            };
        }
        fields_conf
    }


}