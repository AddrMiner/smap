

/// 通过 外部数据包(如果存在内层数据包即为外层ip报文首部中的ttl, 如果没有内层数据包,即为当前数据包首部中的),推断目标主机的 默认ttl
#[inline]
pub fn infer_default_ttl_by_outer_ttl(outer_ip_ttl:u8) -> u8 {

    // 注意:
    // windows 默认ttl 为 128, 2000以前的早期版本可能为32
    // linux 默认ttl 为 64

    match outer_ip_ttl {
        0..=64 => 64,
        65..=128 => 128,
        _ => 255,
    }
}

/// 使用 目标主机 的 默认起始ttl, 推断 目标主机的操作系统
#[allow(dead_code)]
#[inline]
pub fn infer_os_by_default_ttl(ttl:u8) -> String {
    match ttl {
        64 => String::from("linux, macos...etc"),
        128 => String::from("windows"),
        _ => String::from("others")
    }
}

/// 使用 距离 和 接收数据包的ttl, 计算 目标主机的默认起始ttl
#[inline]
pub fn get_default_ttl(distance:u8, recv_ttl:u8) -> u16 {
    (recv_ttl as u16) + ((distance as u16) - 1)
}