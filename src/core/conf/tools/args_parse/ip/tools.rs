use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use ahash::AHashSet;

/// 判断一个 ip范围 是不是 v4 版本
pub fn is_ipv4_range(addrs_str:&str) -> bool {

    let first_addr_str = addrs_str.split(|c| c == '/' || c == '-').next()
        .unwrap().trim(); // 这里无论如何都会存在值，如果报错建议仔细检查


    match Ipv4Addr::from_str(first_addr_str) {

        Ok(_) => true,
        Err(_) => false
    }

}

#[allow(dead_code)]
pub fn ipv4_set_to_vec(set:AHashSet<Ipv4Addr>) -> Vec<Ipv4Addr> {

    let mut ip_vec = vec![];
    for i in set.into_iter() {
        ip_vec.push(i);
    }

    ip_vec
}

#[allow(dead_code)]
pub fn ipv6_set_to_vec(set:AHashSet<Ipv6Addr>) -> Vec<Ipv6Addr> {

    let mut ip_vec = vec![];
    for i in set.into_iter() {
        ip_vec.push(i);
    }

    ip_vec
}

#[allow(dead_code)]
pub fn ip_set_to_vec(set:AHashSet<IpAddr>) -> Vec<IpAddr> {

    let mut ip_vec = vec![];
    for i in set.into_iter() {
        ip_vec.push(i);
    }

    ip_vec
}