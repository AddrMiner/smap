use std::process::exit;
use ahash::AHashSet;
use log::error;
use crate::SYS;
use crate::tools::others::parse::parse_str;

/// 解析数据范围
/// a-b => (a,b)
pub fn parse_u8_range(u8_str:&str) -> (u8, u8) {


    let s:Vec<&str> = u8_str.trim().split('-').collect();

    if s.len() == 2 {  // 两个

        let first:u8 = parse_str(s[0].trim());
        let end:u8 = parse_str(s[1].trim());

        if first <= end {
            return (first, end);
        }else {
            error!("{} {}", SYS.get_info("err", "parse_u8_range_err"), u8_str);
            exit(1)
        }

    }else if s.len() == 1 { // 只有一个

        let single:u8 = parse_str(s[0].trim());
        return (single, single);
    }else {
        error!("{} {}", SYS.get_info("err", "parse_u8_range_err"), u8_str);
        exit(1)
    }

}

/// 解析整体范围 set格式 (随机顺序)
/// a-b, c-d, e  => a..b  c..d e   or  * => 0..255(不按顺序)
pub fn parse_u8_set(u8_str:&str) -> AHashSet<u8> {

    let u8_str = u8_str.trim();

    let mut u8_set = AHashSet::new();

    if u8_str == "*" {

        for ui in 0..=u8::MAX {
            u8_set.insert(ui);
        }

    } else {

        let s:Vec<&str> = u8_str.split(',').collect();

        for ps in s {   // 每个端口范围分段

            let (first, last) = parse_u8_range(ps);

            for pi in first..=last {

                u8_set.insert(pi);
            }
        }
    }

    u8_set
}