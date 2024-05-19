use crate::SYS;
use std::process::exit;
use std::str::FromStr;
use ahash::AHashSet;
use log::error;
use crate::tools::others::parse::parse_str;

/// 解析范围
/// a-b => (a,b)
pub fn parse_range<T:PartialOrd + Copy + FromStr>(ports_str:&str, info:&str) -> (T, T) {


    let s:Vec<&str> = ports_str.trim().split('-').collect();

    if s.len() == 2 {  // 两个端口

        let first:T = parse_str(s[0].trim());
        let end:T = parse_str(s[1].trim());

        if first <= end {
            return (first, end);
        }else {
            error!("{} {}", SYS.get_info("err", info), ports_str);
            exit(1)
        }

    }else if s.len() == 1 { // 只有一个端口

        let single:T = parse_str(s[0].trim());
        return (single, single);
    }else {
        error!("{} {}", SYS.get_info("err", info), ports_str);
        exit(1)
    }

}

/// 解析整体的端口范围 set格式 (随机顺序)
/// a-b, c-d, e  => a..b  c..d e   or  * => 0..65535(不按顺序)
#[allow(dead_code)]
pub fn parse_ports_set(ports_str:&str) -> AHashSet<u16> {

    let ports_str = ports_str.trim();

    let mut ports_set = AHashSet::new();

    if ports_str == "*" {

        // 打乱顺序地添加所有端口
        for pi in 0..=0xFF_FFu16 {
            ports_set.insert(pi);
        }

    } else {

        let s:Vec<&str> = ports_str.split(',').collect();

        for ps in s {   // 每个端口范围分段

            let (first, last) = parse_range(ps, "parse_ports_range_err");

            for pi in first..=last {

                ports_set.insert(pi);
            }
        }
    }

    ports_set
}


/// 解析整体的端口范围 vec格式 (随机顺序)
/// a-b, c-d, e  => a..b  c..d e   or  * => 0..65535(不按顺序)
pub fn parse_ports_vec(ports_str:&str) -> Vec<u16> {

    let ports_str = ports_str.trim();

    let mut ports_set = AHashSet::new();

    if ports_str == "*" {

        // 打乱顺序地添加所有端口
        for pi in 0..=0xFF_FFu16 {
            ports_set.insert(pi);
        }

    } else {

        let s:Vec<&str> = ports_str.split(',').collect();

        for ps in s {   // 每个端口范围分段

            let (first, last) = parse_range(ps, "parse_ports_range_err");

            for pi in first..=last {

                ports_set.insert(pi);
            }
        }
    }

    let mut ports_vec = vec![];
    for port in ports_set.into_iter() {
        ports_vec.push(port);
    }

    ports_vec
}



