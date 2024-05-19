mod cycle_group;
mod file_reader;
mod pmap;
mod topo;
mod ipv6_space_tree;

pub use cycle_group::cycle_group::cycle_group_ipv4::CycleIpv4;
pub use cycle_group::cycle_group::cycle_group_ipv6::CycleIpv6;
pub use cycle_group::cycle_group::cycle_group_ipv4_pattern::CycleIpv4Pattern;
pub use cycle_group::cycle_group::cycle_group_ipv6_pattern::CycleIpv6Pattern;

pub use cycle_group::cycle_group_with_port::cycle_group_ipv4::CycleIpv4Port;
pub use cycle_group::cycle_group_with_port::cycle_group_ipv6::CycleIpv6Port;
pub use cycle_group::cycle_group_with_port::cycle_group_ipv6_pattern::CycleIpv6PatternPort;

pub use file_reader::read_target_file::TargetFileReader;
pub use file_reader::v4::ipv4_file_reader::Ipv4FileReader;
pub use file_reader::v6::ipv6_file_reader::Ipv6FileReader;


pub use pmap::PmapGraph;
pub use pmap::PmapState;
pub use pmap::PmapIpStruct;
pub use pmap::PmapIterV4;
pub use pmap::PmapIterV6;

pub use topo::TopoStateChainV4;
pub use topo::TopoIterV4;

pub use topo::TopoStateChainV6;
pub use topo::TopoIterV6;

pub use ipv6_space_tree::IPv6SpaceTree;



pub enum  CycleIpv4Type {
    CycleIpv4(CycleIpv4),
    CycleIpv4Port(CycleIpv4Port)
}

pub enum CycleIpv6Type {
    CycleIpv6(CycleIpv6),
    CycleIpv6Port(CycleIpv6Port)
}

pub enum CycleIpv6PatternType {
    CycleIpv6Pattern(CycleIpv6Pattern),
    CycleIpv6PatternPort(CycleIpv6PatternPort)
}



/// ipv4迭代器范式, 一般用于 网络层及以下协议 或 自分配端口 的迭代算法
pub trait Ipv4Iter {
    /// 返回值: 0:是否为<u>非最终值</u>, 1:最终值是否有效, 2:ip地址
    fn get_first_ip(&mut self) -> (bool, bool, u32);

    /// 返回值: 0:是否为<u>非最终值</u>, 1:最终值是否有效, 2:ip地址
    fn get_next_ip(&mut self) -> (bool, bool, u32);
}

/// ipv4迭代器P范式, 一般用于 带端口 的迭代算法
pub trait Ipv4IterP {
    /// 返回值: 0:是否为<u>非最终值</u>, 1:最终值是否有效, 2:ip地址, 3:端口号
    fn get_first_ip_port(&mut self) -> (bool, bool, u32, u16);
    /// 返回值: 0:是否为<u>非最终值</u>, 1:最终值是否有效, 2:ip地址, 3:端口号
    fn get_next_ip_port(&mut self) -> (bool, bool, u32, u16);
}

/// ipv4迭代器F范式, 一般用于文件迭代器
pub trait Ipv4IterF {
    /// 0: 是否为最终值  1:当前值是否有效   2:ip地址
    fn get_next_ip(&mut self) -> (bool, bool, u32);
}


/// ipv4迭代器FP范式, 一般用于文件迭代器
pub trait Ipv4IterFP {
    /// 0: 是否为最终值  1:当前值是否有效   2:ip地址   3:端口
    fn get_next_ip_port(&mut self) -> (bool, bool, u32, u16);
}


/// ipv6迭代器范式, 一般用于 网络层及以下协议 或 自分配端口 的迭代算法
pub trait Ipv6Iter {
    /// 返回值: 0:是否为<u>非最终值</u>, 1:最终值是否有效, 2:ip地址
    fn get_first_ip(&mut self) -> (bool, bool, u128);

    /// 返回值: 0:是否为<u>非最终值</u>, 1:最终值是否有效, 2:ip地址
    fn get_next_ip(&mut self) -> (bool, bool, u128);
}


/// ipv6迭代器P范式, 一般用于 带端口 的迭代算法
pub trait Ipv6IterP {
    /// 返回值: 0:是否为<u>非最终值</u>, 1:最终值是否有效, 2:ip地址, 3:端口号
    fn get_first_ip_port(&mut self) -> (bool, bool, u128, u16);

    /// 返回值: 0:是否为<u>非最终值</u>, 1:最终值是否有效, 2:ip地址, 3:端口号
    fn get_next_ip_port(&mut self) -> (bool, bool, u128, u16);
}

/// ipv6迭代器F范式, 一般用于文件迭代器
pub trait Ipv6IterF {
    ///  0:是否为非最终值, 1:当前值是否有效, 2:ip地址
    fn get_next_ip(&mut self) -> (bool, bool, u128);
}

/// ipv6迭代器FP范式, 一般用于文件迭代器
pub trait Ipv6IterFP {
    ///  0:是否为非最终值, 1:当前值是否有效, 2:ip地址, 3:端口号
    fn get_next_ip_port(&mut self) -> (bool, bool, u128, u16);
}


pub trait Topo4Iter {
    /// 返回值: 0:是否为<u>非最终值</u>, 1:最终值是否有效, 2:ip地址, 3:ttl
    fn get_first_ip_ttl(&mut self) -> (bool, bool, u32, u8);

    /// 返回值: 0:是否为<u>非最终值</u>, 1:最终值是否有效, 2:ip地址, 3:ttl
    fn get_next_ip_ttl(&mut self) -> (bool, bool, u32, u8);
}

pub trait Topo6Iter {
    /// 返回值: 0:是否为<u>非最终值</u>, 1:最终值是否有效, 2:ip地址, 3:ttl
    fn get_first_ip_ttl(&mut self) -> (bool, bool, u128, u8);

    /// 返回值: 0:是否为<u>非最终值</u>, 1:最终值是否有效, 2:ip地址, 3:ttl
    fn get_next_ip_ttl(&mut self) -> (bool, bool, u128, u8);
}
