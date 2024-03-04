use std::net::Ipv6Addr;
use std::process::exit;
use log::error;
use crate::tools::others::parse::parse_str;
use crate::SYS;

/// 解析<u>ipv6模式字符串</u>
/// 输入: ipv6@ a-b, c, d-e 输出示例: <u>ip所占的比特位总数(0)</u>, 将<u>模式字符位置换成0后的值(最小ip)(1)</u>, 掩码(2)(变动位为0,其它为1)
/// 和<u>片段信息(3)</u>, 最大ip  片段信息:  0: 片段长度 1: 片段相对最低位的偏移量
pub fn parse_ipv6_pattern(pattern:&String) -> (u32, u128, u128, Vec<(u32, u32)>, u128) {
    let mut ip_parts = pattern.split("@");

    let ip: Ipv6Addr = match ip_parts.next() {
        None => {
            error!("{} {}", SYS.get_info("err", "parse_ipv6_pattern_err"), pattern);
            exit(1)
        }
        Some(s) => {
            match s.trim().parse() {
                Ok(i) => i,
                Err(_) => {
                    error!("{} {}", SYS.get_info("err", "parse_ipv6_pattern_err"), pattern);
                    exit(1)
                }
            }
        }
    };

    let parts_str = match ip_parts.next() {
        None => {
            error!("{} {}", SYS.get_info("err", "parse_ipv6_pattern_err"), pattern);
            exit(1)
        }
        Some(s) => {
            s.trim()
        }
    };

    parse_pattern_whole_range_v6(u128::from(ip), parts_str)
}


fn parse_pattern_whole_range_v6(raw_ip:u128, parts_str:&str) -> (u32, u128, u128, Vec<(u32, u32)>, u128) {

    let mut bits_for_ip = 0;
    let mut parts:Vec<(u32, u32)> = vec![];


    let s:Vec<&str> = parts_str.split(',').collect();

    let mut mask:u128 = u128::MAX;
    let mut pre_last:u32 = 0;
    for ps in s {   // 每个片段

        let (first, last) = parse_pattern_local_range_v6(ps);

        if pre_last >= first {
            // 当前片段的首索引 必须 大于上一个片段的 尾索引
            error!("{} {}", SYS.get_info("err", "ipv6_pattern_local_part_err"), ps);
            exit(1)
        } else {
            pre_last = last;
        }

        let part_len = last  - first + 1;
        let left_move_len = 128 - last;

        bits_for_ip += part_len;
        parts.push((part_len, left_move_len));

        //cur_mask:[  1..                         |   0.. (片段大小)  |  1..          ]

        //  mask1: [  1.. (128 - 片段大小 - 偏移量)  |  0.. (片段大小)  |  0.. (偏移量)   ]
        //  mask2: [  0.. (128 - 片段大小 - 偏移量)  |  0..            |  1.. (偏移量)   ]
        //         [  (128 - 偏移量) 或 片段最后一个元素的索引([1,128])   |    (偏移量)     ]

        let mut mask1;
        let mask1_left_move = part_len + left_move_len;
        if mask1_left_move == 128 {
            mask1 = 0;
        } else {
            mask1 = u128::MAX;
            mask1 = mask1 << mask1_left_move;
        }

        let mut mask2;
        if last == 128 {
            mask2 = 0;
        } else {
            mask2 = u128::MAX;
            mask2 = (mask2 << last) >> last;
        }


        let cur_mask = mask1 | mask2;

        mask = mask & cur_mask;
    }

    if bits_for_ip == 0 || bits_for_ip > 64 {
        error!("{}", SYS.get_info("err", "ipv6_pattern_bits_for_ip_invalid"));
        exit(1)
    }

    // base_ip_val 也是起始ip
    let base_ip_val = raw_ip & mask;

    let end_ip_val = base_ip_val | (!mask);

    (bits_for_ip, base_ip_val, mask, parts, end_ip_val)
}


pub fn parse_pattern_local_range_v6(part_str:&str) -> (u32, u32) {


    let s:Vec<&str> = part_str.trim().split('-').collect();

    if s.len() == 2 {

        let first:u32 = parse_str(s[0].trim());
        let end:u32 = parse_str(s[1].trim());

        if first <= end && 1 <= first && first <= 128 && 1 <= end && end <= 128{
            return (first, end);
        } else {
            error!("{} {}", SYS.get_info("err", "ipv6_pattern_local_part_err"), part_str);
            exit(1)
        }

    }else if s.len() == 1 {

        let single:u32 = parse_str(s[0].trim());
        if 1 <= single && single <= 128 {
            return (single, single);
        } else {
            error!("{} {}", SYS.get_info("err", "ipv6_pattern_local_part_err"), part_str);
            exit(1)
        }

    }else {
        error!("{} {}", SYS.get_info("err", "ipv6_pattern_local_part_err"), part_str);
        exit(1)
    }

}