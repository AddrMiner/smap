use std::process::exit;
use log::error;
use crate::SYS;

pub fn get_topo_message(text:String, allow_repeat:bool, err_info:&str, len:usize) -> Vec<u8> {

    let payload = text.as_bytes();

    if payload.len() < len {

        if allow_repeat {

            let repeat_count = (len / payload.len()) + 1;

            let mut p = Vec::with_capacity(repeat_count * payload.len());
            for _ in 0..repeat_count {
                p.extend_from_slice(payload);
            }

            return p
        } else {
            error!("{}", SYS.get_info("err", err_info));
            exit(1)
        }
    }
    Vec::from(payload)
}