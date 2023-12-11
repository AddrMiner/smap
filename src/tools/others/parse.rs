use std::process::exit;
use std::str::FromStr;
use log::error;
use crate::SYS;

/// 把 string 解析成 指定类型
#[allow(dead_code)]
pub fn parse_string<T : FromStr>(val:&String) -> T {

    let res = val.parse::<T>();

    match res {
        Ok(r) => r,
        Err(_) => {
            error!("{} {}",SYS.get_info("err", "parse_str_failed"), val);
            exit(1)
        }
    }

}

/// 将 &str 解析成 指定类型
pub fn parse_str<T : FromStr>(val:&str) -> T {

    let res = val.parse::<T>();

    match res {
        Ok(r) => r,
        Err(_) => {
            error!("{} {}",SYS.get_info("err", "parse_str_failed"), val);
            exit(1)
        }
    }

}


