use crate::create_fields;

pub struct TcpFields {

    pub source_addr:bool,       // 源地址
    pub sport:bool,             // 源端口

    pub tcp_fields_exist:bool,  // 是否存在 tcp协议字段

    pub dport:bool,             // 目的端口

    pub sequence_num:bool,      // 顺序号
    pub ack_num:bool,           // 应答号

    pub window_size:bool,         // 窗口大小
    pub classification:bool,      // 分类

    pub icmp_responder:bool,    //
    pub icmp_type:bool,         // icmp 类型
    pub icmp_code:bool,         // icmp 代码
    pub icmp_unreach:bool,

    pub len:usize,
}


impl TcpFields {

    pub fn new(fields:&Vec<String>) -> Self {
        let mut fields_conf = Self {
            source_addr: false,
            sport: false,

            tcp_fields_exist: false,

            dport: false,
            sequence_num: false,
            ack_num: false,
            window_size: false,

            icmp_responder: false,
            icmp_type: false,
            icmp_code: false,
            icmp_unreach: false,

            classification: false,

            len: 0,
        };

        create_fields!(fields_conf; fields;
        source_addr,
        sport);

        create_fields!(fields_conf; fields;{
            fields_conf.tcp_fields_exist = true;
        };
        dport,
        sequence_num,
        ack_num,
        window_size);

        create_fields!(fields_conf; fields;
        icmp_responder,icmp_type,
        icmp_code,
        icmp_unreach);

        create_fields!(fields_conf; fields;
            classification);

        if fields_conf.len == 0 {

            // 如果无任何字段匹配, 默认打出所有字段
            fields_conf = Self {
                source_addr: true,
                sport: true,

                tcp_fields_exist: true,

                dport: true,
                sequence_num: true,
                ack_num: true,
                window_size: true,

                icmp_responder: true,
                icmp_type: true,
                icmp_code: true,
                icmp_unreach: true,

                classification: true,
                len: 11,
            };
        }
        fields_conf
    }



}