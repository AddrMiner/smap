use std::net::{Ipv4Addr, Ipv6Addr};
use ahash::AHashSet;
use std::process::exit;
use log::error;
use crate::core::conf::tools::args_parse::ip::ipv4::{parse_ipv4_cycle_group, parse_ipv4_range};
use crate::core::conf::tools::args_parse::ip::ipv6::{parse_ipv6_cycle_group, parse_ipv6_range};
use crate::core::conf::tools::args_parse::ip::tools::is_ipv4_range;
use crate::SYS;
use crate::tools::net_handle::net_type::net_v4::Netv4;
use crate::tools::net_handle::net_type::net_v6::Netv6;

/// 解析 混合地址 范围 (不按顺序)
/// a-b(ipv4), c-d(ipv6), e, f/10(ipv4) => (ipv4_vec:a..b  e 前缀为10的ipv4子网f, ipv6_vec: c..d)
pub fn parse_mix_ip_range_ipaddr(input_addrs_str:&str) -> (Vec<Ipv4Addr>, Vec<Ipv6Addr>) {

    let mut addrs_set_v4 = AHashSet::new();
    let mut addrs_set_v6 = AHashSet::new();

    let addrs_strs:Vec<&str> = input_addrs_str.trim().split(',').collect();

    for addrs_str in addrs_strs {

        // 对每个分段进行ipv4检查
        if is_ipv4_range(addrs_str) {

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
                addrs_set_v4.insert(Ipv4Addr::from(addr));
            }

        } else {

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
                addrs_set_v6.insert(Ipv6Addr::from(addr));
            }
        }
    }

    let mut vec_v4 = vec![];
    for addr_v4 in addrs_set_v4.into_iter() {
        vec_v4.push(addr_v4);
    }

    let mut vec_v6 = vec![];
    for addr_v6 in addrs_set_v6.into_iter() {
        vec_v6.push(addr_v6);
    }


    (vec_v4, vec_v6)
}

/// 返回值: 0:ipv4目标范围(start_ip, end_ip, tar_ip_num), 1:ipv6目标范围,
/// 2:ipv4:(最小ip,最大ip,总数量), 3:ipv6:(最小ip,最大ip,总数量), 4:ipv4和ipv6的总数量之和
pub fn parse_mix_v4_v6_cycle_group(input_addrs_str:&str) -> (Vec<(u32, u32, u64)>, Vec<(u128, u128, u64)>, (u32, u32, u64), (u128, u128, u64), u64) {

    let mut vec_v4 = vec![];
    let mut vec_v6 = vec![];

    let addrs_strs:Vec<&str> = input_addrs_str.trim().split(',').collect();

    for addrs_str in addrs_strs {

        // 对每个分段进行ipv4检查
        if is_ipv4_range(addrs_str) {
            vec_v4.push(parse_ipv4_cycle_group(addrs_str));
        } else {
            vec_v6.push(parse_ipv6_cycle_group(addrs_str));
        }
    }

    let mut total_num_v4:u128 = 0;
    let mut min_ip_v4:u32 = u32::MAX;
    let mut max_ip_v4:u32 = 0;
    for (c_start_ip, c_end_ip, v4_num) in vec_v4.iter() {

        if *c_start_ip < min_ip_v4 {
            min_ip_v4 = *c_start_ip;
        }

        if *c_end_ip > max_ip_v4 {
            max_ip_v4 = *c_end_ip;
        }

        total_num_v4 += *v4_num as u128;
    }

    if total_num_v4 == 0 {
        min_ip_v4 = 0;
        max_ip_v4 = 0;
    }

    let mut total_num_v6:u128 = 0;
    let mut min_ip_v6:u128 = u128::MAX;
    let mut max_ip_v6:u128 = 0;
    for (c_start_ip, c_end_ip, v6_num) in vec_v6.iter() {

        if *c_start_ip < min_ip_v6 {
            min_ip_v6 = *c_start_ip;
        }

        if *c_end_ip > max_ip_v6 {
            max_ip_v6 = *c_end_ip;
        }

        total_num_v6 += *v6_num as u128;
    }

    if total_num_v6 == 0 {
        min_ip_v4 = 0;
        max_ip_v6 = 0;
    }

    let total_num = total_num_v4 + total_num_v6;
    if total_num > (u64::MAX as u128) {
        // 如果 ipv4 和 ipv6 的 目标ip总数之和 大于 u64::MAX
        error!("{}", SYS.get_info("err", "tar_num_over_range"));
        exit(1)
    }

    (vec_v4, vec_v6, (min_ip_v4, max_ip_v4, total_num_v4 as u64), (min_ip_v6, max_ip_v6, total_num_v6 as u64), total_num as u64)
}