use std::net::Ipv6Addr;
use std::process::exit;
use ahash::AHashSet;
use log::error;
use crate::core::conf::tools::args_parse::target_iterator::TarIterBaseConf;
use crate::tools::others::parse::parse_str;
use crate::SYS;
use crate::tools::net_handle::net_type::net_v6::Netv6;

/// 解析 ipv6地址 范围
/// a-b  => (a,b)
pub fn parse_ipv6_range(addrs:&str) -> (Ipv6Addr, Ipv6Addr){

    let s:Vec<&str> = addrs.trim().split('-').collect();

    if s.len() == 2 {  // 两个地址

        let first:Ipv6Addr = parse_str(s[0].trim());
        let end:Ipv6Addr = parse_str(s[1].trim());

        if first <= end {
            return (first, end);
        }else {
            error!("{} {}", SYS.get_info("err","parse_ipv6_range_err"), addrs);
            exit(1)
        }

    }else if s.len() == 1 { // 只有一个地址

        let single:Ipv6Addr = parse_str(s[0].trim());
        return (single, single);
    }else {
        error!("{} {}", SYS.get_info("err","parse_ipv6_range_err"), addrs);
        exit(1)
    }

}



/// 解析 ipv6地址范围 (按顺序, 适用于 循环群算法(zmap) )
/// a-b 或 f/10  => u128: (a, b)  或 u128: ( f子网第一个有效地址, f子网最后一个有效地址 )
pub fn parse_ipv6_cycle_group(addrs_str:&str) -> (u128, u128, u64){

    let addrs_str = addrs_str.trim();

    let first;
    let end;
    if addrs_str.contains('/') {
        let net_v6 = Netv6::from_str(addrs_str);
        first = net_v6.first();
        end = net_v6.last();
    } else {
        let ips = parse_ipv6_range(addrs_str);
        first = ips.0;
        end = ips.1;
    }

    let first_tar = u128::from(first);
    let end_tar = u128::from(end);

    (first_tar, end_tar, TarIterBaseConf::get_tar_ip_num_u128(first_tar, end_tar))
}






/// 解析 ipv6( ipv6 -> u128 )地址 范围 (不按顺序)
/// ipv6: a-b, c-d, e, f/10 => u128: a..b c..d  e 前缀为10的子网f
#[allow(dead_code)]
pub fn parse_ipv6_range_u128(input_addrs_str:&str) -> AHashSet<u128> {

    let mut addrs_set = AHashSet::new();

    let addrs_strs:Vec<&str> = input_addrs_str.trim().split(',').collect();

    for addrs_str in addrs_strs {

        let first;
        let end;
        if addrs_str.contains('/') {
            let net_v6 = Netv6::from_str(addrs_str);
            first = net_v6.first();
            end = net_v6.last();
        } else {
            let ips = parse_ipv6_range(addrs_str);
            first = ips.0;
            end = ips.1;
        }

        let first = u128::from(first);
        let end = u128::from(end);

        for addr in first..=end {

            addrs_set.insert(addr);
        }

    }

    addrs_set
}


/// 解析 ipv6( ipv6 -> ipv6 )地址 范围 (不按顺序)
/// ipv6: a-b, c-d, e, f/10 => ipv6: a..b c..d  e 前缀为10的子网f
#[allow(dead_code)]
pub fn parse_ipv6_range_ipaddr(input_addrs_str:&str) -> AHashSet<Ipv6Addr>{

    let mut addrs_set = AHashSet::new();

    let addrs_strs:Vec<&str> = input_addrs_str.trim().split(',').collect();

    for addrs_str in addrs_strs {

        let first;
        let end;
        if addrs_str.contains('/') {
            let net_v6 = Netv6::from_str(addrs_str);
            first = net_v6.first();
            end = net_v6.last();
        } else {
            let ips = parse_ipv6_range(addrs_str);
            first = ips.0;
            end = ips.1;
        }

        let first = u128::from(first);
        let end = u128::from(end);

        for addr in first..=end {

            addrs_set.insert(Ipv6Addr::from(addr));
        }

    }

    addrs_set
}