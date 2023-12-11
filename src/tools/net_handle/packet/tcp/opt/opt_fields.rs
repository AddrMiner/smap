use crate::create_fields;

pub struct TcpOptFields {

    pub source_addr:bool,

    pub tcp_fields_exist:bool,

    pub sport:bool,
    pub dport:bool,
    pub seq_num:bool,
    pub ack_num:bool,
    pub window:bool,


    pub tcp_opt_exist:bool,

    pub opt_text:bool,

    pub tcp_mss:bool,

    pub ts_val:bool,
    pub ts_ecr:bool,
    pub ts_diff:bool,

    pub qs_func:bool,
    pub qs_ttl:bool,
    pub qs_nonce:bool,

    pub echo:bool,
    pub echo_reply:bool,

    pub ws_cale:bool,

    pub mp_tcp_key:bool,
    pub mp_tcp_diff:bool,

    pub tfo_cookie:bool,

    pub classification:bool,

    pub bytes:bool,

    pub len:usize,
}

impl TcpOptFields {

    pub fn new(fields:&Vec<String>) -> Self {
        let mut fields_conf = Self {
            source_addr: false,
            sport: false,

            tcp_fields_exist: false,

            dport: false,
            seq_num: false,
            ack_num: false,
            window: false,

            tcp_opt_exist: false,

            opt_text: false,
            tcp_mss: false,
            ts_val: false,
            ts_ecr: false,
            ts_diff: false,
            qs_func: false,
            qs_ttl: false,
            qs_nonce: false,
            echo: false,
            echo_reply: false,
            ws_cale: false,
            mp_tcp_key: false,
            mp_tcp_diff: false,
            tfo_cookie: false,
            classification: false,
            bytes: false,
            len: 0,
        };

        create_fields!(fields_conf; fields;
            source_addr,
            sport);

        create_fields!(fields_conf; fields; {
            fields_conf.tcp_fields_exist = true;
        };
            dport,
            seq_num,
            ack_num,
            window);

        create_fields!(fields_conf; fields; {
            fields_conf.tcp_opt_exist = true;
        };
            opt_text,
            tcp_mss,
            ts_val,
            ts_ecr,
            ts_diff,
            qs_func,
            qs_ttl,
            qs_nonce,
            echo,
            echo_reply,
            ws_cale,
            mp_tcp_key,
            mp_tcp_diff,
            tfo_cookie);

        create_fields!(fields_conf; fields;
            classification,
            bytes);

        if fields_conf.len == 0 {
            fields_conf = Self {
                source_addr: true,

                tcp_fields_exist: true,

                sport: true,
                dport: true,
                seq_num: true,
                ack_num: true,
                window: true,

                tcp_opt_exist: true,

                opt_text: true,
                tcp_mss: true,
                ts_val: true,
                ts_ecr: true,
                ts_diff: true,
                qs_func: true,
                qs_ttl: true,
                qs_nonce: true,
                echo: true,
                echo_reply: true,
                ws_cale: true,
                mp_tcp_key: true,
                mp_tcp_diff: true,
                tfo_cookie: true,

                classification: true,
                bytes: true,
                len: 22,
            }
        }
        fields_conf
    }

}

