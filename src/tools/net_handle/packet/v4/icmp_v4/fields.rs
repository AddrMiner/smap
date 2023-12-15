use crate::create_fields;

pub struct IcmpV4Fields {

    pub source_addr:bool,
    pub outer_source_addr:bool,

    pub icmp_fields_exist:bool,

    pub icmp_type:bool,
    pub icmp_code:bool,
    pub identifier:bool,
    pub sequence_num:bool,

    pub classification:bool,

    pub len:usize,
}


impl IcmpV4Fields {

    pub fn new(fields:&Vec<String>) -> Self {

        let mut fields_conf = Self {
            source_addr: false,
            outer_source_addr: false,

            icmp_fields_exist: false,
            icmp_type: false,
            icmp_code: false,
            identifier: false,
            sequence_num: false,
            classification: false,
            len: 0,
        };

        create_fields!(fields_conf; fields; source_addr, outer_source_addr);

        create_fields!(fields_conf; fields;
            {
                fields_conf.icmp_fields_exist = true;
            };
            icmp_type,
            icmp_code,
            identifier,
            sequence_num);

        create_fields!(fields_conf; fields; classification);

        if fields_conf.len == 0 {

            // 如果无任何字段匹配, 默认打出所有字段
            fields_conf = Self {
                source_addr: true,
                outer_source_addr: true,

                icmp_fields_exist: true,

                icmp_type: true,
                icmp_code: true,
                identifier: true,
                sequence_num: true,
                classification: true,
                len: 7,
            };
        }
        fields_conf
    }



    /// 使用icmp类型和代码得到对应提示字段
    pub fn parse_icmp4_classification(icmp_type:u8, _icmp_code:u8) -> String {

        match icmp_type {

            3 => {
                // 目的不可达
                String::from("unreach")
            }

            4 => {
                // 源点抑制
                String::from("source_quench")
            }

            5 => {
                // 重定向
                String::from("redirect")
            }

            8 => {
                // 回送请求消息
                String::from("echo_request")
            }

            11 => {
                // 超时
                String::from("time_exceed")
            }

            0 => {
                String::from("echo_reply")
            }

            _ => {
                // 如果为别的值
                String::from("other")
            }
        }
    }


}