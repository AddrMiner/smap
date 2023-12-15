use crate::create_fields;

pub struct IcmpV6Fields {

    pub source_addr:bool,
    pub outer_source_addr:bool,

    pub icmp_fields_exist:bool,

    pub icmp_type:bool,
    pub icmp_code:bool,
    pub identifier:bool,
    pub sequence:bool,
    pub classification:bool,

    pub len:usize,
}


impl IcmpV6Fields {


    pub fn new(fields:&Vec<String>) -> Self {

        let mut fields_conf = Self {
            source_addr: false,
            outer_source_addr: false,

            icmp_fields_exist: false,

            icmp_type: false,
            icmp_code: false,
            identifier: false,
            sequence: false,

            classification: false,

            len: 0,
        };

        create_fields!(fields_conf; fields; source_addr, outer_source_addr);

        create_fields!(fields_conf; fields; {
            fields_conf.icmp_fields_exist = true;
        }; icmp_type, icmp_code, identifier, sequence);

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
                sequence: true,
                classification: true,
                len: 7,
            };
        }
        fields_conf
    }



    /// 使用icmp类型和代码得到对应提示字段
    pub fn parse_icmp6_classification(icmp_type:u8, icmp_code:u8) -> String {

        match icmp_type {
            1 => {
                // 目标不可达
                match icmp_code {
                    0 => {
                        // 没有到达目的结点的路由，路由器无法转发
                        String::from("unreach_no_route")
                    }

                    1 => {
                        // 路由器或防火墙的管理策略上禁止与某个目的结点通信
                        String::from("unreach_admin")
                    }

                    2 => {
                        // 未指定
                        String::from("unreach_beyond_scope")
                    }

                    3 => {
                        // 因链路或无法解析到目的结点链路层地址，导致目的地址不可到达
                        String::from("unreach_addr")
                    }

                    4 => {
                        // IPv6分组己经传送到目的IP结点，但是不能递交给目的TCP或UDP端口的端口不可到达
                        String::from("unreach_no_port")
                    }

                    5 => {
                        String::from("unreach_policy")
                    }

                    6 => {
                        String::from("unreach_reject_route")
                    }

                    7 => {
                        String::from("unreach_err_src_route")
                    }

                    _ => {
                        // 如果为别的值
                        String::from("unreach")
                    }
                }
            }

            2 => {
                // 分组太长
                String::from("too_big")
            }

            3 => {
                // 超时报文
                String::from("time_exceed")
            }

            4 => {
                // 参数问题报文
                String::from("param_problem")
            }

            _ => {
                // 如果为别的值
                String::from("other")
            }
        }
    }


}