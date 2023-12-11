

pub struct TcpOptFieldsText {

    pub tcp_mss:u16,

    // 时间戳
    pub ts_val:u32,
    pub ts_ecr:u32,
    // 前两个时间戳相同, 该值为 false; 前两个时间戳不同, 该值为true;
    pub ts_diff:bool,

    pub qs_func:u8,
    pub qs_ttl:u8,
    pub qs_nonce:u32,

    pub echo:u32,
    pub echo_reply:u32,

    pub ws_cale:u8,

    pub mp_tcp_key:String,
    pub mp_tcp_diff:bool,

    pub tfo_cookie:String,
}

impl TcpOptFieldsText {

    pub fn new() -> Self {

        Self {
            tcp_mss: 0,

            ts_val: 0,
            ts_ecr: 0,
            ts_diff: true,

            qs_func: 0,
            qs_ttl: 0,
            qs_nonce: 0,
            echo: 0,
            echo_reply: 0,
            ws_cale: 0,
            mp_tcp_key: "--".to_string(),
            mp_tcp_diff: true,
            tfo_cookie: "".to_string(),
        }

    }


}