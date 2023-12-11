use std::net::Ipv6Addr;
use std::process::exit;
use log::error;
use crate::SYS;
use crate::tools::others::parse::parse_str;

pub struct Netv6{
    ip:Ipv6Addr,
    pub mask:u8,
}


impl Netv6 {

    /// 构造一个带掩码的 v6 网络地址
    /// 网络地址会根据输入的 ip 和 掩码 自动计算
    pub fn new(ip:Ipv6Addr, mask:u8) -> Self {

        // 如果超出 32 直接报错
        if mask > 128 {
            error!("{} {} {}", SYS.get_info("err", "ipv6_net_invalid"), ip, mask);
            exit(1)
        }

        // 如果 mask 为 0, 直接返回 0 ip
        if mask == 0 {
            return Netv6 {
                ip:Ipv6Addr::from(0),
                mask
            }
        }

        let ip_val = u128::from(ip);
        let move_bits = 128 - mask;

        let net_val = ( ip_val >> move_bits ) << move_bits;

        Netv6 {
            ip:Ipv6Addr::from(net_val),
            mask
        }
    }


    /// 从 str 生成 v6 网络地址
    pub fn from_str(raw_net_str:&str) -> Self {

        let mut net_mask = raw_net_str.trim().split("/");

        let net_str;
        let mask_str;
        if let Some(n) = net_mask.next() {
            net_str = n;
        } else {
            error!("{} {}", SYS.get_info("err","parse_ipv6_net_failed"), raw_net_str);
            exit(1)
        }

        if let Some(m) = net_mask.next() {
            mask_str = m;
        } else {
            error!("{} {}", SYS.get_info("err","parse_ipv6_net_failed"), raw_net_str);
            exit(1)
        }

        if let Some(_) = net_mask.next() {      // 检查合法性
            error!("{} {}", SYS.get_info("err","parse_ipv6_net_failed"), raw_net_str);
            exit(1)
        }

        let ip:Ipv6Addr = parse_str(net_str);
        let mask:u8 = parse_str(mask_str);

        Netv6::new(ip, mask)

    }


    /// 获取 第一个 可用地址
    pub fn first(&self) -> Ipv6Addr {

        // 如果 是一个ip地址, 就返回本身;
        // 如果只有 0(网络地址) 和 1(广播地址) 的子网，就返回 0 对应的 地址
        if self.mask >= 127 {
            return self.ip
        }

        let ip_val = u128::from(self.ip);

        Ipv6Addr::from( ip_val + 1 )
    }

    /// 获取 最后一个 可用地址
    pub fn last(&self) -> Ipv6Addr {

        // 如果是 整个网络, 返回 最大值-1
        if self.mask == 0 {
            return Ipv6Addr::from( u128::MAX - 1 )
        }

        // 如果是一个 ip地址 直接返回本身
        if self.mask == 128 {
            return self.ip
        }

        let ip_val = u128::from(self.ip);

        // 如果 子网中只有 0 和 1, 返回 1 对应的地址
        if self.mask == 127 {
            return Ipv6Addr::from( ip_val + 1 )
        }

        let next_add = 1 << (128 - self.mask);

        let broad_ip_val = ip_val + (next_add - 2);

        Ipv6Addr::from(broad_ip_val)

    }


    /// 获取 广播 地址
    #[allow(dead_code)]
    pub fn broadcast(&self) -> Option<Ipv6Addr> {

        // 如果 是一个ip地址 或者 只有 0(网络地址) 和 1(广播地址) 的子网， 则不存在 广播地址
        if self.mask >= 127 {
            return None
        }

        // 如果 mask 为 0, 表示整个网络, 广播地址为 最大数
        if self.mask == 0 {
            return Some(Ipv6Addr::from( u128::MAX ))
        }


        let ip_val = u128::from(self.ip);

        let next_add = 1 << (128 - self.mask);

        let broad_ip_val = ip_val + (next_add - 1);

        Some(Ipv6Addr::from(broad_ip_val))

    }

    /// 获取 网络 地址
    #[allow(dead_code)]
    pub fn net(&self) -> Option<Ipv6Addr>{

        // 如果 是一个ip地址 或者 只有 0(网络地址) 和 1(广播地址) 的子网
        // 则不存在 网络地址
        if self.mask >= 127 {
            None
        } else {
            Some(self.ip)
        }

    }

}
