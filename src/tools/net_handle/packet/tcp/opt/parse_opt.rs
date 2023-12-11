use crate::tools::net_handle::packet::tcp::opt::opt_fields::TcpOptFields;
use crate::tools::net_handle::packet::tcp::opt::opt_fields_text::TcpOptFieldsText;


impl TcpOptFields {

    pub fn parse_tcp_opt(option_bytes:&[u8]) -> (String, TcpOptFieldsText) {

        let mut option_text = String::new();
        let mut fields_text = TcpOptFieldsText::new();

        let option_bytes_len = option_bytes.len();

        let mut index = 0;
        while index < option_bytes_len {

            match option_bytes[index] {

                0 => {
                    // 结束
                    if option_bytes[(index + 1)..(index + 4)].eq(&[0u8;3]) {
                        option_text.push_str("E-");
                    } else {
                        option_text.push_str("X");
                    }
                    break
                }

                1 => {
                    // NDP
                    option_text.push_str("N-");
                    index += 1;
                }

                2 => {
                    // MSS
                    if option_bytes[index + 1] == 4 {
                        option_text.push_str("MSS-");
                        fields_text.tcp_mss = ((option_bytes[index + 2] as u16) << 8) | (option_bytes[index + 3] as u16);
                        index += 4;
                    } else {
                        option_text.push_str("MXX-");
                        break
                    }
                }

                3 => {
                    // Window Scale
                    option_text.push_str("WS-");
                    fields_text.ws_cale = option_bytes[index + 2];
                    index += 3;
                }

                4 => {
                    // SACK permitted
                    option_text.push_str("SACK-");
                    index += 2;
                }

                6 => {
                    // Echo Request
                    option_text.push_str("ECHO-");
                    fields_text.echo = u32::from_be_bytes(
                        [option_bytes[index + 2], option_bytes[index + 3],option_bytes[index + 4],option_bytes[index + 5]]
                    );
                    index += 6;
                }

                7 => {
                    // Echo Reply
                    option_text.push_str("ECHOR-");
                    fields_text.echo_reply = u32::from_be_bytes(
                        [option_bytes[index + 2], option_bytes[index + 3],option_bytes[index + 4],option_bytes[index + 5]]
                    );
                    index += 6;
                }

                8 => {
                    // timestamps
                    if option_bytes[index + 1] == 0x0a {
                        option_text.push_str("TS-");

                        fields_text.ts_val = u32::from_be_bytes(
                            [option_bytes[index + 2], option_bytes[index + 3],option_bytes[index + 4],option_bytes[index + 5]]
                        );
                        fields_text.ts_ecr = u32::from_be_bytes(
                            [option_bytes[index + 6], option_bytes[index + 7],option_bytes[index + 8],option_bytes[index + 9]]
                        );
                        fields_text.ts_diff = fields_text.ts_val != fields_text.ts_ecr;

                        index += 10;
                    } else {
                        option_text.push_str("TXX-");
                        break
                    }
                }

                27 => {
                    // Quick Start/ Response
                    option_text.push_str("QS-");

                    fields_text.qs_func = option_bytes[index + 2] >> 4;
                    fields_text.qs_ttl = option_bytes[index + 3];
                    let qs_nonce_left_2 = u32::from_be_bytes(
                        [option_bytes[index + 4], option_bytes[index + 5],option_bytes[index + 6],option_bytes[index + 7]]
                    );
                    fields_text.qs_nonce = qs_nonce_left_2 >> 2;

                    index += 8;
                }

                30 => {
                    // MP TCP
                    option_text.push_str("MPTCP-");

                    let mp_tcp_key = u64::from_be_bytes(
                        [option_bytes[index + 4], option_bytes[index + 5],option_bytes[index + 6],option_bytes[index + 7],
                            option_bytes[index + 8], option_bytes[index + 9],option_bytes[index + 10],option_bytes[index + 11]]
                    );
                    fields_text.mp_tcp_key = String::from(format!("{:?}", &option_bytes[(index + 4)..(index + 12)]));
                    fields_text.mp_tcp_diff = mp_tcp_key != 0x0c0c0c0c0c0c0c0c;

                    index += option_bytes[index + 1] as usize;
                }

                34 => {
                    // TFO
                    let opt_len:usize = option_bytes[index + 1] as usize;
                    if option_bytes[index + 1] > 2 {
                        option_text.push_str("TFOC-");
                        fields_text.mp_tcp_diff = false;

                        let mut cook_last_index_add_one = index + opt_len;
                        if cook_last_index_add_one > 40 { cook_last_index_add_one = 40; }

                        fields_text.tfo_cookie = String::from(format!("{:?}", &option_bytes[(index + 2)..cook_last_index_add_one]));
                    } else {
                        option_text.push_str("TFOE-");
                    }
                    index += opt_len;
                }

                64 => {
                    // unknown option sent by us
                    option_text.push_str("U-");
                    index += 2;
                }

                5 => {
                    // SACK, only permitted in SYN
                    option_text.push_str("X");
                    index += option_bytes[index + 1] as usize;
                }

                9 => {
                    // obsolete
                    option_text.push_str("X");
                    index += 2;
                }

                10 | 14 => {
                    // obsolete
                    option_text.push_str("X");
                    index += 3;
                }

                15 => {
                    // SACK, only permitted in SYN
                    option_text.push_str("X");
                    index += option_bytes[index + 1] as usize;
                }

                18 => {
                    // obsolete
                    option_text.push_str("X");
                    index += 3;
                }

                19 => {
                    // obsolete
                    option_text.push_str("X");
                    index += 18;
                }

                28 => {
                    // obsolete
                    option_text.push_str("X");
                    index += 4;
                }

                253 | 254 => {
                    // experimental
                    option_text.push_str("X");
                    index += option_bytes[index + 1] as usize;
                }

               _ => {
                   option_text.push_str("X-");
                   break
               }
            }
        }

        (option_text, fields_text)
    }


}




