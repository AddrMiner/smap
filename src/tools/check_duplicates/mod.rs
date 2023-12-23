pub mod bit_map_v4;
pub mod bit_map_v6;
pub mod bit_map_v6_pattern;
pub mod bit_map_v4_port;
pub mod bit_map_v6_port;
pub mod bit_map_v6_pattern_port;




pub trait DuplicateCheckerV4 {

    /// 对ip进行存在标记
    fn set(&mut self, ip:u32);

    /// 如果没被标记,返回true
    /// 如果被标记或超出目标范围,返回false
    fn not_marked_and_valid(&self, ip:u32) -> bool;
}


pub trait DuplicateCheckerV6 {

    /// 对ip进行存在标记
    fn set(&mut self, ip:u128);

    /// 如果没被标记,返回true
    /// 如果被标记或超出目标范围,返回false
    fn not_marked_and_valid(&self, ip:u128) -> bool;
}


pub trait DuplicateCheckerV4Port {

    /// 对ip端口对进行存在标记
    fn set(&mut self, ip:u32, port:u16);

    /// 如果没被标记,返回true
    /// 如果被标记或超出目标范围,返回false
    fn not_marked_and_valid(&self, ip:u32, port:u16) -> bool;
}

pub trait DuplicateCheckerV6Port {

    /// 对ip端口对进行存在标记
    fn set(&mut self, ip:u128, port:u16);

    /// 如果没被标记,返回true
    /// 如果被标记或超出目标范围,返回false
    fn not_marked_and_valid(&self, ip:u128, port:u16) -> bool;
}