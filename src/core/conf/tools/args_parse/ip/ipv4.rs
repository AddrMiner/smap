use std::net::Ipv4Addr;
use std::process::exit;
use ahash::AHashSet;
use log::error;
use crate::core::conf::tools::args_parse::target_iterator::TarIterBaseConf;
use crate::tools::others::parse::parse_str;
use crate::SYS;
use crate::tools::net_handle::net_type::net_v4::Netv4;

/// 解析 ipv4地址 范围
/// a-b  => (a,b)
pub fn parse_ipv4_range(addrs:&str) -> (Ipv4Addr, Ipv4Addr){


    let s:Vec<&str> = addrs.trim().split('-').collect();

    if s.len() == 2 {  // 两个地址

        let first:Ipv4Addr = parse_str(s[0].trim());
        let end:Ipv4Addr = parse_str(s[1].trim());

        if first <= end {
            return (first, end);
        }else {
            error!("{} {}", SYS.get_info("err","parse_ipv4_range_err"), addrs);
            exit(1)
        }

    }else if s.len() == 1 { // 只有一个地址

        let single:Ipv4Addr = parse_str(s[0].trim());
        return (single, single);

    }else {
        error!("{} {}", SYS.get_info("err","parse_ipv4_range_err"), addrs);
        exit(1)
    }

}

/// 解析<u>ipv4地址范围</u>(按顺序)
/// 返回值: 0: 起始地址 1: 最终地址 2: 目标范围ip地址总数
/// a-b 或 f/10  => u32: (a, b)  或 u32: ( f子网第一个有效地址, f子网最后一个有效地址 )
pub fn parse_ipv4_cycle_group(addrs_str:&str) -> (u32, u32, u64){

    let addrs_str = addrs_str.trim();

    let first;
    let end;
    if addrs_str.contains('/') {
        let net_v4 = Netv4::from_str(addrs_str);
        first = net_v4.first();
        end = net_v4.last();
    } else {
        let ips = parse_ipv4_range(addrs_str);
        first = ips.0;
        end = ips.1;
    }

    let first_tar = u32::from(first);
    let end_tar = u32::from(end);

    (first_tar, end_tar, TarIterBaseConf::get_tar_ip_num_u32(first_tar, end_tar))
}

/// 解析 ipv4( ipv4 -> u32)地址 范围 (不按顺序)
/// ipv4: a-b, c-d, e, f/10  => u32: a..b c..d  e 前缀为10的子网f
#[allow(dead_code)]
pub fn parse_ipv4_range_u32(input_addrs_str:&str) -> AHashSet<u32> {

    let mut addrs_set = AHashSet::new();

    let addrs_strs:Vec<&str> = input_addrs_str.trim().split(',').collect();

    for addrs_str in addrs_strs {

        let first;
        let end;
        if addrs_str.contains('/') {
            let net_v4 = Netv4::from_str(addrs_str);
            first = net_v4.first();
            end = net_v4.last();
        } else {
            let ips = parse_ipv4_range(addrs_str);
            first = ips.0;
            end = ips.1;
        }

        let first = u32::from(first);
        let end = u32::from(end);

        for addr in first..=end {

            addrs_set.insert(addr);
        }

    }

    addrs_set
}

/// 解析 ipv4( ipv4 -> ipv4 )地址 范围 (不按顺序)
/// ipv4: a-b, c-d, e, f/10 => ipv4: a..b c..d  e 前缀为10的子网f
#[allow(dead_code)]
pub fn parse_ipv4_range_ipaddr(input_addrs_str:&str) -> AHashSet<Ipv4Addr> {

    let mut addrs_set = AHashSet::new();

    let addrs_strs:Vec<&str> = input_addrs_str.trim().split(',').collect();

    for addrs_str in addrs_strs {

        let first;
        let end;
        if addrs_str.contains('/') {
            let net_v4 = Netv4::from_str(addrs_str);
            first = net_v4.first();
            end = net_v4.last();
        } else {
            let ips = parse_ipv4_range(addrs_str);
            first = ips.0;
            end = ips.1;
        }

        let first = u32::from(first);
        let end = u32::from(end);

        for addr in first..=end {

            addrs_set.insert(Ipv4Addr::from(addr));
        }

    }

    addrs_set
}


